package introspection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/polyglotdev/mcp-auth-go"
)

// maxBodyBytes caps the introspection response read so a hostile or
// misconfigured endpoint cannot OOM the resource server. This is the inbound
// auth gate -- with caching off (the default) it is hit on every request.
const maxBodyBytes = 1 << 20 // 1 MiB

const defaultTokenTypeHint = "access_token"

// Constant log causes. They never contain the token, the response body, or the
// AS-supplied iss/aud -- the no-leak discipline (a wrapped cause reaches the
// operator log via (*auth.Error).Error(), but never the client body).
var (
	errInactive         = errors.New("token inactive")
	errIssuerMismatch   = errors.New("issuer mismatch")
	errAudienceMismatch = errors.New("audience mismatch")
	errExpired          = errors.New("token expired")
)

// Config configures a Validator. IntrospectionURL, ClientAuth, Issuer, and
// Audience are required; the rest have safe defaults.
type Config struct {
	// IntrospectionURL is the issuer's RFC 7662 endpoint
	// (e.g. https://acme.okta.com/oauth2/default/v1/introspect). REQUIRED. It
	// MUST be https (RFC 7662 section 4 -- the client secret and the opaque
	// token travel on this request); http is allowed only for a loopback host
	// (a same-host sidecar/mesh terminating TLS elsewhere, and tests).
	IntrospectionURL string

	// ClientAuth authenticates the resource server TO the introspection
	// endpoint. REQUIRED: RFC 7662 section 4 mandates a protected endpoint so it
	// is never a token-scanning oracle.
	ClientAuth ClientAuthenticator

	// Issuer is the expected iss in the introspection response. REQUIRED; the
	// response's iss must equal it byte-for-byte.
	Issuer string

	// Audience is the expected aud. REQUIRED; the response's aud must contain it
	// (exact string match) -- the confused-deputy / RFC 8707 audience defense.
	Audience string

	// TokenTypeHint is the optional RFC 7662 token_type_hint. The zero value
	// defaults to "access_token" (an explicit omit control is out of scope; the
	// hint is only an authorization-server optimization).
	TokenTypeHint string

	// Cache is optional; nil => no caching, so every Validate hits the AS and a
	// revoked token is rejected immediately (the secure default). When set,
	// entries are bounded by the response exp (RFC 7662 section 4).
	Cache Cache

	// HTTPClient is optional; the default has a 30s timeout.
	HTTPClient *http.Client

	// ClockSkew tolerates clock drift on the defense-in-depth exp check.
	// Defaults to 30s.
	ClockSkew time.Duration

	// Now is optional; defaults to time.Now (injected for tests).
	Now func() time.Time
}

// Validator validates opaque bearer tokens via an RFC 7662 introspection
// endpoint and returns typed *auth.Claims. It satisfies auth.TokenValidator, so
// it drops into the same transports a JWT auth.Validator does. Construct it with
// NewValidator; it is read-only after construction and safe for concurrent use.
type Validator struct {
	url        string
	clientAuth ClientAuthenticator
	issuer     string
	audience   string
	hint       string
	cache      Cache
	httpClient *http.Client
	clockSkew  time.Duration
	now        func() time.Time
}

var _ auth.TokenValidator = (*Validator)(nil)

// NewValidator validates cfg and fills defaults. It makes no network call:
// introspection is per-token and lazy, so (unlike auth.NewValidator) it takes no
// ctx and primes nothing. It returns an error if a required field is missing or
// if IntrospectionURL is not an https (or loopback-http) URL.
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.IntrospectionURL == "" {
		return nil, errors.New("introspection: Config.IntrospectionURL is required")
	}
	if cfg.ClientAuth == nil {
		return nil, errors.New("introspection: Config.ClientAuth is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("introspection: Config.Issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("introspection: Config.Audience is required")
	}
	if err := checkURL(cfg.IntrospectionURL); err != nil {
		return nil, err
	}

	hint := cfg.TokenTypeHint
	if hint == "" {
		hint = defaultTokenTypeHint
	}
	clockSkew := cfg.ClockSkew
	if clockSkew <= 0 {
		clockSkew = 30 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &Validator{
		url:        cfg.IntrospectionURL,
		clientAuth: cfg.ClientAuth,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		hint:       hint,
		cache:      cfg.Cache,
		httpClient: httpClient,
		clockSkew:  clockSkew,
		now:        now,
	}, nil
}

// checkURL requires https, or http only for a loopback host. RFC 7662 section 4:
// the client secret and the token travel on this request; cleartext to a
// non-loopback host would expose both.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("introspection: Config.IntrospectionURL is not a valid URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errors.New("introspection: Config.IntrospectionURL must be https (loopback http is allowed)")
}

// isLoopbackHost reports whether host is a loopback literal. "localhost" is
// matched as a literal string and never resolved -- a DNS lookup could be
// poisoned to point localhost at a remote host.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Validate validates a bearer token by introspecting it. It returns typed
// *auth.Claims on success, or a typed *auth.Error: auth.ErrMissingToken (empty
// bearer), auth.ErrInvalidToken (inactive, or iss/aud mismatch or absent),
// auth.ErrExpiredToken (past exp), or ErrIntrospectionUnavailable (the endpoint
// could not be reached or returned an undecodable/non-200 response). It makes at
// most one HTTP request and is safe for concurrent use.
//
// The returned Claims carry the authorization server's trust level: an opaque
// token has no local signature, so Email and the Raw extension claims are
// unauthenticated values from the introspection response. Use Subject as the
// identity; never make an authorization decision on Email or Raw.
func (v *Validator) Validate(ctx context.Context, bearer string) (*auth.Claims, error) {
	if bearer == "" {
		return nil, auth.ErrMissingToken
	}

	var key string
	if v.cache != nil {
		key = cacheKey(bearer)
		if claims, ok := v.cache.Get(key); ok {
			return claims, nil
		}
	}

	form := url.Values{"token": {bearer}}
	form.Set("token_type_hint", v.hint) // always set: NewValidator defaults an empty hint

	resp, body, err := v.do(ctx, form)
	if err != nil {
		return nil, err
	}

	// Authentication checks. The AS answering active:true is not sufficient: the
	// resource server confirms the issuer and audience itself (an introspection
	// endpoint may report a token minted for another resource as active), and
	// fails closed when either is absent. Causes are constants (no token/AS text).
	if !resp.Active {
		return nil, auth.ErrInvalidToken.With(errInactive)
	}
	if resp.Iss != v.issuer { // byte-exact; "" (absent) fails closed
		return nil, auth.ErrInvalidToken.With(errIssuerMismatch)
	}
	if !audienceContains(resp.Aud, v.audience) { // byte-exact membership; nil/empty fails closed
		return nil, auth.ErrInvalidToken.With(errAudienceMismatch)
	}
	if resp.Exp > 0 && v.now().After(time.Unix(resp.Exp, 0).Add(v.clockSkew)) {
		return nil, auth.ErrExpiredToken.With(errExpired)
	}

	claims := claimsFrom(resp, body)
	// Cache only when exp is present, so the entry is time-bounded (RFC 7662
	// section 4: a response MUST NOT be cached beyond its exp).
	if v.cache != nil && resp.Exp > 0 {
		v.cache.Set(key, claims)
	}
	return claims, nil
}

// do performs one HTTP POST and returns the decoded response plus the raw body
// (buffered for the Raw second pass), or a typed *auth.Error. Client auth is
// applied BEFORE the body is encoded so a body-mutating FormPost is included.
func (v *Validator) do(ctx context.Context, form url.Values) (*introspectionResponse, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, nil)
	if err != nil {
		return nil, nil, Unavailable(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if err := v.clientAuth.Apply(req, form); err != nil {
		return nil, nil, Unavailable(fmt.Errorf("client auth: %w", err))
	}
	enc := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(enc))
	req.ContentLength = int64(len(enc))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(enc)), nil }

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, nil, Unavailable(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, Unavailable(fmt.Errorf("read introspection response: %w", err))
	}
	// Fail-secure: no body content is trusted unless the AS answered 200. RFC
	// 7662 reports a valid-but-inactive token as 200 active:false, never a 4xx.
	if resp.StatusCode != http.StatusOK {
		return nil, nil, Unavailable(fmt.Errorf("introspection endpoint returned %d", resp.StatusCode))
	}
	var ir introspectionResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, nil, Unavailable(fmt.Errorf("decode introspection response: %w", err))
	}
	return &ir, body, nil
}

// introspectionResponse is the subset of RFC 7662 section 2.2 members the
// validator consumes. It deliberately omits error/error_description so AS error
// text cannot enter a trusted field.
type introspectionResponse struct {
	Active bool     `json:"active"`
	Scope  string   `json:"scope"`
	Sub    string   `json:"sub"`
	Iss    string   `json:"iss"`
	Aud    audience `json:"aud"`
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
	Email  string   `json:"email"`
	Cnf    struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

// audience decodes the RFC 7662 / RFC 7519 aud member, which may be a single
// string or an array of strings (absent or null => nil).
type audience []string

// UnmarshalJSON accepts a JSON string, a JSON array of strings, or null.
func (a *audience) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*a = nil
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []string
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return err
		}
		*a = arr
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		*a = audience{s}
	default:
		return errors.New("aud must be a string or array of strings")
	}
	return nil
}

// audienceContains reports whether auds contains want by exact string equality.
// Empty elements never match a configured (non-empty) want, so they are ignored.
func audienceContains(auds audience, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}

// extractedKeys are the response members mapped explicitly (or deliberately
// dropped). Every other JSON-string member is captured into Claims.Raw, matching
// core claimsFromToken. error/error_description are skipped so an AS error string
// can never land in Raw.
var extractedKeys = map[string]struct{}{
	"active": {}, "scope": {}, "sub": {}, "iss": {}, "aud": {}, "exp": {},
	"iat": {}, "nbf": {}, "email": {}, "cnf": {}, "token_type": {},
	"client_id": {}, "username": {}, "jti": {}, "error": {}, "error_description": {},
}

// claimsFrom maps a 200 introspection response to *auth.Claims. body is the
// buffered response bytes, re-decoded to capture extra string members into Raw.
func claimsFrom(r *introspectionResponse, body []byte) *auth.Claims {
	c := &auth.Claims{
		Subject:      r.Sub,
		Email:        r.Email,
		Issuer:       r.Iss,
		Audience:     []string(r.Aud),
		Confirmation: r.Cnf.Jkt,
		Scopes:       strings.Fields(r.Scope),
		Raw:          map[string]string{},
	}
	if r.Exp > 0 {
		c.ExpiresAt = time.Unix(r.Exp, 0)
	}
	if r.Iat > 0 {
		c.IssuedAt = time.Unix(r.Iat, 0)
	}

	var rest map[string]json.RawMessage
	if err := json.Unmarshal(body, &rest); err == nil {
		for k, raw := range rest {
			if _, skip := extractedKeys[k]; skip {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				c.Raw[k] = s
			}
		}
	}
	return c
}

// cacheKey is the non-reversible token digest used as the cache key. The raw
// token (a secret) is never a map key.
func cacheKey(bearer string) string {
	sum := sha256.Sum256([]byte(bearer))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
