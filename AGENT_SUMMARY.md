# csar-core Agent Summary

## Role In Prod
`csar-core` is the shared Go primitive layer for the entire stack. It supplies
gateway identity parsing, JWKS verification, STS router clients, HTTP helpers,
TLS helpers, config loading, S3 storage, audit/notify clients, health checks,
Postgres utilities, and secret redaction.

## Runtime Entry Points
- This repo is library-first; its packages are imported by `csar`, `csar-authn`,
  `csar-authz`, `csar-audit`, `csar-notify`, `csar-botverify`, and the aurum
  services.
- The practical entrypoints are package APIs such as `gatewayctx`, `jwtx`,
  `stsclient`, `httpx`, `httpx/clientx`, `configload`, `configsource`, `tlsx`,
  `observe`, and `pgutil`.

## Trust/Auth Model
- `gatewayctx` parses trusted identity headers, but it is not trust enforcement.
- `TrustedMiddleware` should only be used with mTLS or an equivalent source
  check.
- `stsclient` is the approved service-to-router auth path for router-bound HTTP.
- `jwtx` handles JWT verification and remote JWKS resolution for services that
  consume signed tokens.

## Critical Flows
- Config loading from file, HTTP, or S3 with hash/integrity validation.
- Remote JWKS fetch/cache/refresh on key rotation.
- STS token exchange, bounded router-bound retries, and router-bound client auth.
- Shared inbound/outbound HTTP helpers, including query parsing and capped JSON
  response handling.
- Audit and notify router clients used by multiple services.
- TLS client/server config generation for mTLS-enabled services.

## Config And Secrets
- Env expansion, secret redaction, and Yandex Cloud auth helpers are core
  cross-service primitives.
- S3 object access, IAM token refresh, and TLS file handling should be treated
  as shared security-sensitive behavior.

## Audit Hotspots
- `gatewayctx` trust assumptions are easy to misuse in downstream services.
- `jwtx` is a blast-radius package; changes affect authn, authz, and router
  verification behavior.
- `stsclient`, `httpx`, `httpx/clientx`, `configsource`, and `observe` are shared
  across the ecosystem and require downstream retest when changed.
- Any new shared helper should be justified against existing packages before
  adding a duplicate.

## First Files To Read
- `gatewayctx/gatewayctx.go`
- `jwtx/verify.go`
- `jwtx/jwk_remote.go`
- `stsclient/client.go`
- `stsclient/service.go`
- `httpx/query.go`
- `httpx/clientx/clientx.go`
- `configload/load.go`
- `configsource/builder.go`
- `tlsx/tlsx.go`
- `audit/router_client.go`

## DRY / Extraction Candidates
- If a service needs request identity, JWT/JWKS, router auth, audit, or config
  loading, prefer these packages instead of local copies.
- Cross-repo duplication belongs here first unless it is clearly service-specific.

## Required Quality Gates
- `go build ./...`
- `go test ./... -count=1`
- `golangci-lint run ./...`
- If `csar-core` changes, rerun downstream build/test in `csar`, `csar-authn`,
  and `csar-authz`
