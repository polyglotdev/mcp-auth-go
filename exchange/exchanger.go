package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/polyglotdev/mcp-auth-go/audit"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 URN, not a credential
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // RFC 8693 URN, not a credential
)

// Config configures an Exchanger. TokenURL and ClientAuth are required.
type Config struct {
	TokenURL   string
	ClientAuth ClientAuthenticator
	Cache      Cache            // optional; default per-caller in-memory TTL cache
	HTTPClient *http.Client     // optional; default has a 30s timeout
	Now        func() time.Time // optional; default time.Now (injected for tests)
	Audit      audit.Sink       // optional; nil ⇒ no audit
}

// Exchanger performs RFC 8693 token exchanges against a single AS token endpoint.
type Exchanger struct {
	tokenURL   string
	clientAuth ClientAuthenticator
	cache      Cache
	httpClient *http.Client
	now        func() time.Time
	audit      audit.Sink
}

// NewExchanger validates cfg and fills defaults. It defaults Now to time.Now
// BEFORE building the default Cache so the cache never gets a nil clock.
func NewExchanger(cfg Config) (*Exchanger, error) {
	if cfg.TokenURL == "" {
		return nil, errors.New("exchange: Config.TokenURL is required")
	}
	if cfg.ClientAuth == nil {
		return nil, errors.New("exchange: Config.ClientAuth is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewMemoryCache(now, 30*time.Second)
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Exchanger{
		tokenURL:   cfg.TokenURL,
		clientAuth: cfg.ClientAuth,
		cache:      cache,
		httpClient: httpClient,
		now:        now,
		audit:      cfg.Audit,
	}, nil
}

// Exchange performs one RFC 8693 token exchange. Its identity sourcing is pure:
// it reads identity only from req (never ctx, never by parsing SubjectToken), so
// no token bytes enter the cache key or an audit event. When req.Subject != ""
// it consults and populates the cache under req.Subject|audience|sorted(scope);
// empty Subject => uncached. It emits one audit event per call when a sink is
// configured (granted on success or cache hit; denied/error on failure).
func (x *Exchanger) Exchange(ctx context.Context, req Request) (*Token, error) {
	if req.SubjectToken == "" {
		return nil, errors.New("exchange: Request.SubjectToken is required")
	}

	key := ""
	if req.Subject != "" {
		key = cacheKey(req.Subject, req.Audience, req.SubjectTokenType, req.RequestedTokenType, req.Scope)
		if tok, ok := x.cache.Get(key); ok {
			x.recordGranted(ctx, req, tok)
			return tok, nil
		}
	}

	subjectTokenType := req.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = tokenTypeAccessToken
	}
	form := url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {req.SubjectToken},
		"subject_token_type": {subjectTokenType},
	}
	if req.RequestedTokenType != "" {
		form.Set("requested_token_type", req.RequestedTokenType)
	}
	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}
	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}
	if len(req.Scope) > 0 {
		form.Set("scope", strings.Join(req.Scope, " "))
	}
	if req.ActorToken != "" {
		form.Set("actor_token", req.ActorToken)
		form.Set("actor_token_type", tokenTypeAccessToken)
	}

	tok, err := x.do(ctx, form)
	if err != nil {
		x.recordFailure(ctx, req, err)
		return nil, err
	}
	if key != "" && !tok.ExpiresAt.IsZero() {
		x.cache.Set(key, tok)
	}
	x.recordGranted(ctx, req, tok)
	return tok, nil
}

// RedeemAssertion performs an RFC 7523 jwt-bearer grant: it presents assertion
// (an ID-JAG, or any JWT assertion the endpoint accepts) to the Exchanger's
// configured token endpoint, authenticating with the Exchanger's ClientAuth, and
// returns the issued downstream Token. It is step 2 of the Identity Assertion
// JWT Authorization Grant flow; the Exchanger must be configured for the
// Resource Authorization Server's token endpoint (not the IdP's). It is not
// cached at this level.
func (x *Exchanger) RedeemAssertion(ctx context.Context, assertion string, scope ...string) (*Token, error) {
	if assertion == "" {
		return nil, errors.New("exchange: RedeemAssertion assertion is required")
	}
	form := url.Values{
		"grant_type": {GrantTypeJWTBearer},
		"assertion":  {assertion},
	}
	if len(scope) > 0 {
		form.Set("scope", strings.Join(scope, " "))
	}
	return x.do(ctx, form)
}

// recordGranted audits a successful (fresh or cached) exchange. It carries the
// caller identity and the issued scopes only -- never the subject or issued
// token bytes.
func (x *Exchanger) recordGranted(ctx context.Context, req Request, tok *Token) {
	if x.audit == nil {
		return
	}
	x.audit.Record(ctx, audit.Event{
		Action: audit.ActionTokenExchange, Outcome: audit.OutcomeGranted,
		Subject: req.Subject, Audience: req.Audience, Scopes: tok.Scopes, Time: x.now(),
	})
}

// recordFailure audits a failed exchange: ErrExchangeRejected => denied (AS
// policy), anything else => error (operational). Scopes are the requested set.
func (x *Exchanger) recordFailure(ctx context.Context, req Request, err error) {
	if x.audit == nil {
		return
	}
	outcome, reason := audit.OutcomeError, "exchange_unavailable"
	if errors.Is(err, ErrExchangeRejected) {
		outcome, reason = audit.OutcomeDenied, "exchange_rejected"
	}
	x.audit.Record(ctx, audit.Event{
		Action: audit.ActionTokenExchange, Outcome: outcome, ReasonCode: reason,
		Subject: req.Subject, Audience: req.Audience, Scopes: req.Scope, Time: x.now(),
	})
}

// do POSTs the exchange and performs at most one use_dpop_nonce retry. The retry
// loop lives here (it owns the HTTPClient); the ClientAuthenticator only
// decorates each attempt, receiving the server nonce on the retry.
func (x *Exchanger) do(ctx context.Context, form url.Values) (*Token, error) {
	nonce := ""
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, Unavailable(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if err := x.clientAuth.Apply(req, form, nonce); err != nil {
			return nil, Unavailable(fmt.Errorf("client auth: %w", err))
		}

		resp, err := x.httpClient.Do(req)
		if err != nil {
			return nil, Unavailable(err)
		}

		var body tokenResponse
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		serverNonce := resp.Header.Get("DPoP-Nonce")
		status := resp.StatusCode
		_ = resp.Body.Close()

		if status >= 500 {
			return nil, Unavailable(fmt.Errorf("authorization server returned %d", status))
		}
		if decErr != nil {
			return nil, Unavailable(fmt.Errorf("decode token response: %w", decErr))
		}
		if status == http.StatusOK && body.AccessToken != "" {
			return x.token(body), nil
		}
		if body.Error == "use_dpop_nonce" && serverNonce != "" && attempt == 0 {
			nonce = serverNonce
			continue
		}
		return nil, Rejected(body.Error, body.ErrorDescription)
	}
	return nil, Rejected("use_dpop_nonce", "authorization server kept requesting a new DPoP nonce")
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IssuedTokenType  string `json:"issued_token_type"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (x *Exchanger) token(b tokenResponse) *Token {
	t := &Token{
		AccessToken:     b.AccessToken,
		IssuedTokenType: b.IssuedTokenType,
		TokenType:       b.TokenType,
	}
	if b.ExpiresIn > 0 {
		t.ExpiresAt = x.now().Add(time.Duration(b.ExpiresIn) * time.Second)
	}
	if b.Scope != "" {
		t.Scopes = strings.Fields(b.Scope)
	}
	return t
}

// cacheKey composes the per-caller key. subject is the explicit caller identity
// (never token bytes); scope is sorted for stability. The token-type fields are
// included so an ID-JAG mint and a plain access-token exchange for the same
// caller never share a cache entry.
func cacheKey(subject, audience, subjectTokenType, requestedTokenType string, scope []string) string {
	s := append([]string(nil), scope...)
	sort.Strings(s)
	return subject + "|" + audience + "|" + subjectTokenType + "|" + requestedTokenType + "|" + strings.Join(s, " ")
}
