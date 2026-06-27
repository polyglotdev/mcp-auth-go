package exchange

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/polyglotdev/mcp-auth-go/audit"
)

const (
	// TokenTypeIDJAG is the requested_token_type / issued_token_type URN for the
	// Identity Assertion JWT Authorization Grant. NON-RATIFIED: from
	// draft-ietf-oauth-identity-assertion-authz-grant-04. It is isolated here so a
	// spec revision is a one-line change.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag" //nolint:gosec // draft URN, not a credential
	// TokenTypeIDToken is the RFC 8693 subject_token_type for an OIDC ID Token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // RFC 8693 URN, not a credential
	// TokenTypeSAML2 is the RFC 8693 subject_token_type for a SAML 2.0 assertion.
	TokenTypeSAML2 = "urn:ietf:params:oauth:token-type:saml2" //nolint:gosec // RFC 8693 URN, not a credential
	// TokenTypeRefreshToken is the RFC 8693 subject_token_type for a refresh token.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec // RFC 8693 URN, not a credential
	// GrantTypeJWTBearer is the RFC 7523 grant type used in step 2 to redeem the
	// ID-JAG for a downstream access token at the Resource Authorization Server.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // RFC 7523 URN, not a credential

	// reasonCrossAppAccess marks a granted Cross-App-Access flow in the audit
	// trail, distinguishing it from a plain token exchange without a new
	// audit.Action. It is a bounded reason_code value.
	reasonCrossAppAccess = "cross_app_access"
)

// Endpoint is one OAuth 2.0 token endpoint plus the client authentication and
// (optional) HTTP client used against it.
//
// SECURITY: the IDP and ResourceAS endpoints of a DownstreamTokenProvider are
// DIFFERENT authorization servers in DIFFERENT trust domains. Their ClientAuth
// MUST use DISTINCT credentials -- sharing one BasicAuth (or one client
// id/secret) across both legs transmits the Resource AS's secret to the IDP
// (and vice versa), disclosing a credential to the wrong party. This cannot be
// enforced in code (ClientAuthenticator is opaque); it is a documented,
// reviewed invariant.
type Endpoint struct {
	// TokenURL is the endpoint's token URL. REQUIRED.
	TokenURL string
	// ClientAuth authenticates this client to the endpoint. REQUIRED.
	ClientAuth ClientAuthenticator
	// HTTPClient is optional; the default has a 30s timeout.
	HTTPClient *http.Client
}

// DownstreamConfig configures a DownstreamTokenProvider for the two-step
// Identity Assertion JWT Authorization Grant (Cross App Access) flow.
type DownstreamConfig struct {
	// IDP is the enterprise IDP token endpoint that mints the ID-JAG (step 1).
	IDP Endpoint
	// ResourceAS is the Resource Authorization Server token endpoint that
	// redeems the ID-JAG for a downstream access token (step 2).
	ResourceAS Endpoint
	// Audience is the Resource AS issuer identifier, sent as the step-1
	// `audience`. REQUIRED.
	Audience string
	// Resource is the target resource (MCP server) identifier, sent as the
	// optional step-1 `resource`.
	Resource string
	// Scope is the requested downstream scope set, sent on both legs. Optional.
	Scope []string
	// SubjectTokenType is the RFC 8693 subject_token_type for step 1. Optional;
	// defaults to TokenTypeIDToken.
	SubjectTokenType string
	// Cache is optional; nil => the final downstream token is not cached (every
	// Provide runs both legs). When set, entries are bounded by the token exp.
	Cache Cache
	// Now is optional; defaults to time.Now (injected for tests).
	Now func() time.Time
	// Audit is optional; nil => no audit. One event is recorded per Provide.
	Audit audit.Sink
}

// nopCache is a stateless Cache that never stores anything. The provider gives
// it to its inner Exchangers so the intermediate ID-JAG and downstream token
// are never cached at that layer -- the provider owns the only (final-token)
// cache. NewExchanger defaults a nil Cache to a live MemoryCache, so an explicit
// no-op cache is required to disable inner caching.
type nopCache struct{}

func (nopCache) Get(string) (*Token, bool) { return nil, false }
func (nopCache) Set(string, *Token)        {}

// DownstreamTokenProvider obtains a downstream access token via the two-step
// Identity Assertion JWT Authorization Grant flow: it exchanges a subject
// identity assertion for an ID-JAG at the IDP (RFC 8693), then redeems the
// ID-JAG for an access token at the Resource Authorization Server (RFC 7523).
// Construct it with NewDownstreamProvider; it is read-only after construction
// and safe for concurrent use.
//
// The Resource AS validates the ID-JAG (draft-04 section 4.4.1) and the MCP
// server's token validator validates the resulting access token; this provider
// performs no local cryptographic validation of either.
type DownstreamTokenProvider struct {
	idp              *Exchanger
	resourceAS       *Exchanger
	audience         string
	resource         string
	subjectTokenType string
	scope            []string
	cache            Cache
	now              func() time.Time
	audit            audit.Sink
}

// NewDownstreamProvider validates cfg and fills defaults. It makes no network
// call. It builds two internal Exchangers with caching disabled (the provider
// owns the only cache) and a nil audit sink (the provider audits once per
// Provide). It returns an error if a required field is missing.
func NewDownstreamProvider(cfg DownstreamConfig) (*DownstreamTokenProvider, error) {
	if cfg.IDP.TokenURL == "" {
		return nil, errors.New("exchange: DownstreamConfig.IDP.TokenURL is required")
	}
	if cfg.IDP.ClientAuth == nil {
		return nil, errors.New("exchange: DownstreamConfig.IDP.ClientAuth is required")
	}
	if cfg.ResourceAS.TokenURL == "" {
		return nil, errors.New("exchange: DownstreamConfig.ResourceAS.TokenURL is required")
	}
	if cfg.ResourceAS.ClientAuth == nil {
		return nil, errors.New("exchange: DownstreamConfig.ResourceAS.ClientAuth is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("exchange: DownstreamConfig.Audience is required")
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	subjectTokenType := cfg.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = TokenTypeIDToken
	}
	// Defensive copy: a caller that later mutates its Scope slice must not change
	// what the provider sends, keys the cache on, or records in audit events.
	scope := append([]string(nil), cfg.Scope...)

	idp, err := NewExchanger(Config{
		TokenURL:   cfg.IDP.TokenURL,
		ClientAuth: cfg.IDP.ClientAuth,
		HTTPClient: cfg.IDP.HTTPClient,
		Now:        now,
		Cache:      nopCache{},
		Audit:      nil,
	})
	if err != nil {
		return nil, err
	}
	resourceAS, err := NewExchanger(Config{
		TokenURL:   cfg.ResourceAS.TokenURL,
		ClientAuth: cfg.ResourceAS.ClientAuth,
		HTTPClient: cfg.ResourceAS.HTTPClient,
		Now:        now,
		Cache:      nopCache{},
		Audit:      nil,
	})
	if err != nil {
		return nil, err
	}

	return &DownstreamTokenProvider{
		idp:              idp,
		resourceAS:       resourceAS,
		audience:         cfg.Audience,
		resource:         cfg.Resource,
		subjectTokenType: subjectTokenType,
		scope:            scope,
		cache:            cfg.Cache,
		now:              now,
		audit:            cfg.Audit,
	}, nil
}

// ProvideRequest is one Cross-App-Access token acquisition.
type ProvideRequest struct {
	// SubjectAssertion is the caller's enterprise identity assertion (an OIDC ID
	// Token, a SAML2 assertion, or a refresh token, per SubjectTokenType).
	// REQUIRED. It is a secret: never logged, never a cache key.
	SubjectAssertion string
	// Subject is the explicit cache-key identity (the caller's sub). Optional;
	// empty => this acquisition is not cached. It is NEVER derived from
	// SubjectAssertion -- supply it explicitly.
	Subject string
}

// Provide runs the two-step flow and returns the downstream access token. It
// exchanges req.SubjectAssertion for an ID-JAG at the IDP (step 1), then redeems
// the ID-JAG for an access token at the Resource Authorization Server (step 2).
// When req.Subject is non-empty and a Cache is configured, it consults and
// populates the cache under req.Subject|audience|scope; a step-1 failure returns
// without attempting step 2. It records one audit event per call.
//
// The returned Token.AccessToken is the downstream access token, audience-
// restricted to the resource named in the flow. The subject assertion, the
// intermediate ID-JAG, and the issued token are secrets and never appear in an
// error, an audit event, or a cache key.
func (p *DownstreamTokenProvider) Provide(ctx context.Context, req ProvideRequest) (*Token, error) {
	if req.SubjectAssertion == "" {
		return nil, errors.New("exchange: ProvideRequest.SubjectAssertion is required")
	}

	key := ""
	if p.cache != nil && req.Subject != "" {
		key = cacheKey(req.Subject, p.audience, "", "", p.scope)
		if tok, ok := p.cache.Get(key); ok {
			p.recordGranted(ctx, req.Subject, tok)
			return tok, nil
		}
	}

	// Step 1: mint the ID-JAG via RFC 8693 token exchange at the IDP. Subject is
	// empty so the inner exchange is uncached (belt-and-suspenders with nopCache).
	idjag, err := p.idp.Exchange(ctx, Request{
		SubjectToken:       req.SubjectAssertion,
		Subject:            "",
		SubjectTokenType:   p.subjectTokenType,
		RequestedTokenType: TokenTypeIDJAG,
		Audience:           p.audience,
		Resource:           p.resource,
		Scope:              p.scope,
	})
	if err != nil {
		p.recordFailure(ctx, req.Subject, err)
		return nil, err
	}

	// Step 2: redeem the ID-JAG for a downstream access token via RFC 7523
	// jwt-bearer at the Resource Authorization Server.
	tok, err := p.resourceAS.RedeemAssertion(ctx, idjag.AccessToken, p.scope...)
	if err != nil {
		p.recordFailure(ctx, req.Subject, err)
		return nil, err
	}

	if key != "" && !tok.ExpiresAt.IsZero() {
		p.cache.Set(key, tok)
	}
	p.recordGranted(ctx, req.Subject, tok)
	return tok, nil
}

// recordGranted audits a successful (fresh or cached) acquisition. It carries
// the caller identity and issued scopes only -- never the subject assertion, the
// ID-JAG, or the issued token bytes.
func (p *DownstreamTokenProvider) recordGranted(ctx context.Context, subject string, tok *Token) {
	if p.audit == nil {
		return
	}
	p.audit.Record(ctx, audit.Event{
		Action:     audit.ActionTokenExchange,
		Outcome:    audit.OutcomeGranted,
		ReasonCode: reasonCrossAppAccess,
		Subject:    subject,
		Audience:   p.audience,
		Scopes:     tok.Scopes,
		Time:       p.now(),
	})
}

// recordFailure audits a failed acquisition: ErrExchangeRejected => denied (AS
// policy), anything else => error (operational). Scopes are the requested set.
func (p *DownstreamTokenProvider) recordFailure(ctx context.Context, subject string, err error) {
	if p.audit == nil {
		return
	}
	outcome, reason := audit.OutcomeError, "exchange_unavailable"
	if errors.Is(err, ErrExchangeRejected) {
		outcome, reason = audit.OutcomeDenied, "exchange_rejected"
	}
	p.audit.Record(ctx, audit.Event{
		Action:     audit.ActionTokenExchange,
		Outcome:    outcome,
		ReasonCode: reason,
		Subject:    subject,
		Audience:   p.audience,
		Scopes:     p.scope,
		Time:       p.now(),
	})
}
