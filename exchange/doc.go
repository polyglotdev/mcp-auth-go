// Package exchange is an RFC 8693 OAuth 2.0 Token Exchange client. It swaps a
// caller's validated inbound access token for a downstream-service token via any
// RFC 8693 authorization server, with pluggable client authentication (Basic,
// DPoP) and a per-caller token cache.
//
// It depends only on the core auth package (for the shared Error shape and the
// raw-token/claims context helpers) and jwx (DPoP proof signing) -- never on a
// transport. The Exchange method is a pure primitive; TokenForCaller is the
// context-aware convenience over it.
//
// The package also implements the client side of the Identity Assertion JWT
// Authorization Grant (Cross App Access; the basis of MCP Enterprise-Managed
// Authorization). DownstreamTokenProvider runs the two-step flow -- mint an
// ID-JAG via RFC 8693 token exchange at the enterprise IdP, then redeem it via an
// RFC 7523 jwt-bearer grant (RedeemAssertion) at the Resource Authorization
// Server -- returning a downstream access token. The non-ratified draft id-jag
// URN is isolated behind the TokenTypeIDJAG constant.
package exchange
