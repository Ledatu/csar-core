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
- `audit.PrepareEvent` owns JSON payloads and establishes a canonical UUID and
  microsecond timestamp. Retain the prepared event for manual retries; clients
  prepare each ID-less emission separately. HTTP and protobuf preserve the ID.
- TLS client/server config generation for mTLS-enabled services.

## Config And Secrets
- `authnconfig` supports explicit `oauth.enabled: false` without provider
  credentials or a state-cookie secret; omitted flags retain enabled validation.
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


## AMQP confirmation contract
- amqpconfirm.Await requires a dedicated channel with one outstanding mandatory
  publish and buffered return/confirm listeners registered before publication.
  Returned, NACKed and closed receipts fail; a returned message wins over its ACK.
- Audit and the aurumskynet-core wrapper share this primitive. Notify remains
  unchanged. Release this package before pinning standalone consumers to it.

## Transactional audit and versioned S3 (source only, October 8)
- `audit.PGOutbox.EnqueueTx` must share the business transaction. Mutation or
  enqueue failure rolls both back. Exact event identity/content is retained
  until synchronous router acceptance; a lost receipt may replay the same ID.
- Relays claim one row using SKIP LOCKED with a 60s fenced lease, 30s send limit
  and capped retry backoff. A stale worker cannot delete another claim. No
  unconfirmed send can remove an outbox event. Startup mode is explicit; shared
  authn/authz configs default `audit_outbox_enabled` to false.
- `StartRouterRelay` owns transport, cancellation/join and backlog collectors.
  Observation failures emit scrape-success=0, without pretending backlog is zero.
- `s3store.PutStream[IfAbsent]`, `StatStreamObject` and `OpenVersion` join validated
  prefixes, bound IO to 64MiB/30s, return version receipts and enforce pinned
  reads. Conditional writes permit verification of an existing object on retry;
  ETag is not a content checksum. IAM requests reject redirects.
- SDK and IAM paths are tested with local HTTP endpoints. Actual destination
  versioning, conditional-write support and protected identities remain rollout
  gates. Legacy 10MiB materialized APIs retain their existing behavior.
- Read `audit/outbox.go`, `audit/outbox_relay.go`, `s3store/stream.go` and the
  guarded localhost integration tests before extending these contracts.

## Legacy sync session endpoint
`legacy_users_sync.lock_database_dsn` is startup-only and required for enabled
PostgreSQL apply. It must select session pooling or direct PostgreSQL; normal
transaction-pooled requests remain independent. This is authn-specific schema,
not a new shared locking primitive. Dry-run does not need this endpoint.

## Email delivery portability (source only, October 11, 2026)
- `email` is the shared transport boundary for Postbox HTTP and Selectel SMTP.
  It owns one-recipient message validation, MIME rendering, verified implicit
  TLS/STARTTLS and bounded AUTH LOGIN submission. Selectel defaults are
  smtp.mail.selcloud.ru:1127 (TLS), or 1126 for STARTTLS; timeout defaults to 10s.
- `email.SendError` distinguishes rejected, retryable and unknown acceptance.
  No transport automatically retries. SMTP receipt success means DATA accepted;
  QUIT failure does not invalidate it. SMTPUTF8 envelope addresses are currently
  unsupported; Unicode display names, subjects and UTF-8 bodies are supported.
- Postbox preserves SendEmail and adds SendEmailWithReceipt. Authenticated HTTP
  redirects are rejected and provider reply bodies are excluded from errors.
- `authnconfig.EmailOTPConfig.Delivery` selects an explicit transport; omission
  preserves legacy Postbox configuration. Mixed legacy/new settings fail validation.
  Legacy and explicit Postbox endpoints both require HTTPS without credentials,
  query or fragment and are validated during config load.
  Notify email and local/direct-MX mail delivery are not enabled by this change.

## Bounded HTTP error diagnostics (October 16, 2026)
- `audit/http_response.go` owns version 1 `metadata.http_response`, JSON diagnostic
  allowlist, mandatory redaction, 64 KiB inspection/4 KiB body budgets and explicit
  omission/truncation states. No raw incomplete/HTML/text fallback is stored.
- Producers capture only final errors on opt-in routes and supply known secrets;
  `jsonredact.RedactText` masks reflected credentials, cookies, URL credentials,
  JWTs and email addresses. It is not a universal PII classifier.
- `audit.EncodeHTTPMetadata` keeps the existing 16 KiB ingest budget, preserving
  status/provenance while dropping optional body/query. Wire and DB unchanged.
- Publish this library before pinning router/coordinator consumers. New capture
  policy remains off until compatible binaries are deployed; old events stay valid.

## HTTP listener lifecycle

`httpserver.Server.IsServing()` reports an active accept loop without probing the
listener. It is false before startup, on bind/serve failure, during shutdown and
after exit. `Serve(listener)` supports pre-bound listeners; servers are single-use.
This replaces TCP self-probes of TLS listeners in downstream health checks. It
does not claim certificate, authenticated HTTP or workload validation.

## Local read reuse (source only, October 23)
- `readcache.Group[T]` owns bounded in-flight admission, follower release and
  ticket completion. CSAR's HTTP cache consumes it; HTTP policy stays in CSAR.
- `readcache.Scope` owns bounded operation-local byte memoization with explicit
  Close and maximum age. Failed loads are not retained; values are copied.
- This is not Redis/distributed coalescing, a freshness policy or seller quota.
  See `readcache/README.md`. Release before pinning downstream consumers.
