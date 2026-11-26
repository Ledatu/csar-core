## Profile-bound public OAuth policy — receiver contract

Optional credentials.public_oauth configures exact public endpoints, profile IDs
and explicit resource aliases. No application URLs/default profiles or mutable
quota namespace exist in Core. Existing loaders reject enabled public policy;
LoadFromBytesWithPublicOAuth is for the matching full receiver. Strict config
rejects ambiguous resources, unknown profiles, incomplete endpoints and issuer-
disabled activation. Dynamic admission implementation/activation stays Authn.

## Account attribution and explicit direct resource use (approved §21, source only)

Origin claims v2 use an explicit subject/credential account binding with no tenant. Credential binding preserves exact profile, original uint64 revision and audience. Gateway headers/contexts own and strictly decode it. The account delegate helper never imports tenant state; tenant helpers reject account bindings. The reserved origin purpose is unchanged and ordinary access verifiers still reject it. New access-resource-v2 has its own reusable access identity/authorized scope contract, never a proof or child token. Production, Redis, deployment and outbound Telegram-ID JWT behavior are unchanged.

## Profile-controlled manual issuance

Optional `manual_issuance` fixes `family: api_key|connection` and `max_ttl` per
credential profile. Omission retains API-key issuance bounded by access/grant TTL.
Explicit maximum is positive whole seconds within grant TTL; connection maxima
are 1–168 hours. Connection uses the existing immutable connection accounting
family without client/code/refresh authority. Request input can only shorten the
fixed deadline; family is server policy. Old strict readers reject the new field; the previous credential receiver also
rejects enabled manual policy. `LoadFromBytesWithManualIssuance` explicitly opts
in only after its runtime enforces these semantics.
No storage, counter, Redis or deployed configuration changes.

## Full service-capability receiver prerequisite (U10)

The explicit `LoadFromBytesWithServiceCapabilities` permits configured decision,
subject/assignment reads and tenant role grant/revoke only with pinned verified
admin TLS ingress. The older default and decide-only loaders keep their activation
restrictions. Runtime handlers must enforce exact per-service operation/profile,
subject mode and resource mapping, with role subsets under the global ceiling.
`ValidateServicePolicyIngress` shares the schema/startup ingress guard; physical
verified chains and peer pin remain per-request checks. No endpoint or deployed
configuration changes here.

## Shared generic issuer preflight

The explicit credential-receiver loader additionally requires secure session
cookies, verified TLS with client CA, and transactional audit before accepting
enabled declarations. This preflight belongs in the shared schema so runtime and
helper validation cannot disagree. Physical trust/store/client readiness remains
an Authn startup check. The default loader still rejects enablement.

## Credential revision compatibility and v2 receiver contract (U05b/U07)

Credential profiles may explicitly accept 1–32 compatible grant revisions,
including the current revision; omitted lists accept only the current one.
Pure Narrow intersects immutable stored consent with current policy without
rewriting the original revision or gaining expanded scopes/namespaces. It grants
no current permission. Runtime loader opt-in accepts enabled declarations only
for a compatible receiver with bounded routed STS decision transport; normal
helper/default loading still rejects activation. Dedicated ingress, session,
store/outbox, atomic startup and live Authz remain receiver responsibilities.
Version-2 delegation request/result values preserve exact namespace/profile,
audience/scope/resource and classified owner/caller bindings. New distinct v2
route modes reject downgrade; v1 types and outbound route-token wire are unchanged.
No runtime or deployed configuration is activated by these primitives.

## Service-decision receiver prerequisites (U03, source only)

`authzconfig.LoadFromBytesWithServiceDecisions` is an explicit receiver opt-in
for enabled `decide` capabilities. The normal/helper loader still rejects enabled
policies, and the decision-only loader rejects enabled list/write capabilities.
Service receivers must enforce pinned trusted ingress, owner/service/profile/
audience/resource matching and startup-only changes before using it.
`httpx.ReadStrictJSON` is an opt-in security-object reader over the existing
decoder: duplicate/case-aliased keys, invalid UTF-8, excessive nesting and trailing
or unknown fields fail without reflecting request values. Legacy `ReadJSON` stays
compatible. Neither API installs endpoints or changes deployed configuration.

## Generic Authz service policy declarations (U02b, source only)

`authzconfig.Config.ServicePolicies` declares fixed permission/audience/namespace
decision profiles and exact per-service operation/profile capabilities. Explicit
request-bound/background modes apply only to subject decisions/scope listing;
assignment reads and tenant role grant/revoke are distinct operations. Role subsets
must exist in policy and intersect `admin.service_assignable_roles`; platform
bindings cannot authorize role writes. Tenant prefixes are delimited and bounded
to preserve exact IDs within 256 bytes; different namespaces cannot alias a tenant
mapping. An explicit platform alternative has empty scope ID and never implies
tenant membership. The existing engine owns all live permission evaluation.
Absent declarations preserve behavior and new `enabled: true` is rejected.
Configuration schema versions are independent of stored consent format versions.
No service HTTP operation, assignment rule, policy, migration or runtime trust
is changed. Later receivers must enforce verified service/owner/namespace bindings,
atomic failure behavior and current authority before lifting activation guards.

## Generic credential profile declarations (U02a, source only)

`authnconfig.Config.Credentials` is an optional versioned declaration: public
HTTPS URLs, exact mutation origins, secure consent cookie, dedicated feature CA/
leaf-CN references, audience/scope/namespace profiles and per-service inspect/
evaluate capabilities. Permission policies remain Authz-owned references.
Omission preserves all current defaults; `enabled: true` is rejected until
receiver integration exists. Disabled declarations are fully validated.
`configutil.UnmarshalYAMLWithEnvStrictSections` scopes known-field validation to
new blocks, rejects null/alias/merge/duplicate ambiguity and multiple documents,
and preserves typed, injection-safe environment expansion. Other existing field
schemas remain unchanged. Runtime certificate verification, session/CSRF/owner
checks and startup/reload enforcement remain with the later service integration.
The new collection checks do not activate issuers or alter current CA trust.

## Universal resource consent contracts (U01, source only)

`authntokens.ResourceRef` separates namespace and opaque literal ID;
`ScopeRef` retains explicit tenant/platform authorization scope. Versioned
`GrantConstraints` validates an explicit consent snapshot with selected refs or
current-and-future resources within its persisted namespace set. Namespace and
ID limits fit existing 256-byte origin/scope references; selectors cap at 256,
decision batches at 100, namespaces at 16 and scopes at 32. JSON envelope bounds
include maximum escaped scope strings. These values establish neither identity,
resource existence nor current permission. Issuers own immutable owner/caller/
family/deadline bindings and must intersect consent with current policy/authority.
Existing delegation/session route-token wire and the outbound Telegram JWT bridge
are unchanged. No new credential, issuer, storage, receiver or policy is activated.

## Explicit Authn issuer trust configuration

`OriginRouterPeerCN` optionally supplies the exact feature-specific verified leaf
name alongside `OriginRouterCAFile`. Omission supplies no application default in
Core; legacy runtime wrappers retain their compatibility policy until migration.
The peer requires an explicitly configured dedicated CA and verified listener.
Both fields are startup-only in Authn. Certificate material is never changed here.

`authnconfig.Config.OriginRouterCAFile` permits a manifest to opt into the existing
dedicated origin issuer without changing a secret-bearing environment file. It
requires a verified client TLS listener; runtime registration still verifies the
separate CA and exact router leaf identity. Empty remains disabled. Services own
startup wiring and restart-only lifecycle; this field grants no access authority.

## Explicit audit request attribution

`audit.WithRequestContext` enriches an owned event from already trusted gateway
context and a valid OTel span. It preserves explicit fields and legacy Actor /
unknown identities, and never infers caller kind from a transport or label. Origin
fields are adopted only for the same caller/operation, avoiding mixed chains.
It does not authenticate headers or change existing Record/outbox behavior;
producers explicitly opt in after validating their ingress/session provenance.
Prepare once afterwards and retain that event across retries.

## Non-replayable CSAR request bodies

`csarclient` clears `GetBody` when `ReplaySafe` is false. A caller idempotency
header cannot grant implicit net/http body replay after a reused connection
closes. Reviewed replay-safe reads retain reconstruction and existing SDK/STS
policy. A real connection-loss regression covers the write path; downstream
router/Authn/Authz build/tests pass. No service/router activation is implied.

## Complete JSON documents (November20)

httpx.ReadJSON now requires EOF after the first decoded value. A second decode
rejects stray closing delimiters and malformed/trailing tokens which dec.More
could accept. Whitespace-only suffixes, field validation and body bounds remain
compatible. This is an existing shared helper correction, not a service decoder
or automatic runtime change. Downstream router/authn/authz build/tests are required.

## Bounded HTTP retries and native pool readiness (November 14)

`httpx/retryafter` centralizes bounded delta-seconds/HTTP-date parsing previously
private to tokenmint. clientx.Error exposes only a sanitized RetryAfter duration,
including consistent CSAR retry_after_ms envelopes, capped at24h. It preserves
credential-plane origin without exposing headers/body in error strings or logs.
Tokenmint reuses the parser and retains its own profile backoff bounds.
`pgutil.PoolReadiness` supplies a bounded, redacted required-dependency check for
module-owned native pools. These primitives do not execute retries or activate a
service. See the OZ08 owner for durable cabinet cooldown policy.

# csar-core Agent Summary

`grpcserver.Shutdown` bounds graceful gRPC drain by the caller's context and
forces transport closure on expiry. Services own long-lived subscription drain,
resource lifetime and the overall deadline; cancellation-ignoring handlers can
outlive forced stop. Real gRPC tests cover successful in-flight completion and
deadline cancellation. No production policy or infrastructure settings change.

origincontext.DelegateClient reuses an existing authenticated STS router client
for the Authn delegation route. WithGatewayParent adopts an opaque parent only
from trusted gateway ingress; every dispatch obtains a child bound to the actual
method/URI/body and receiver. Target/issuer clients support separate audiences;
STS remains shared and independent per client. Refresh waiters honor cancellation
without interrupting an active exchange. Parent expiry
bounds response IO; redirects/retries and off-router targets fail closed. It adds
no service activation, backend access-token verifier or direct Authn connection.

usagebudget supplies atomic Redis multi-dimension weighted usage counters with
bounded fixed windows, units and dimensions. Policy keys share a Cluster slot;
stable subjects are hashed and credentials/transport are excluded. Limit denials
charge nothing; infrastructure uncertainty fails closed without inferred refunds.
Context-aware Redis IO is mandatory; disable driver retries for single-charge
attempts. This is not a concurrency/byte reservation or activation of production.

gatewayctx.Origin forwards a separately owned original caller and canonical
operation chain/expiry under the same trusted ingress boundary. It preserves the
immediate Caller/Subject and shares their bounded codec; ambiguous partial origin
headers fail closed. Raw proofs remain outside typed identity/audit DTOs. Gateway
origincontext proof context pairs a verified token and owned claims atomically;
replacing metadata alone clears the previous token. No forwarding activation.

origincontext.RootClient is gateway-only dedicated HTTPS/mTLS root issuance. It
reuses csarclient/clientx bounds and disables redirects/retries; response signature,
caller/receiver/resource/request digest, root depth and source expiry are checked.
Errors omit issuer bodies and credentials. Call Close to release its cloned
transport; supply bounded trusted-key resolution. No route/runtime activation.

W2 origincontext defines separate attribution JWTs (never access tokens), with
issuer/receiver/purpose, resource and original request digest bindings, bounded
60-second lifetime, depth four and child expiry no later than its parent. Root
issuance requires an independently verified gateway adapter; the package itself
adds no HTTP endpoint, permissions or runtime activation. Verifiers must reject
the reserved token_use on access-token paths before any issuer is activated.
authntokens also carries optional session expiry for bounded validator caches.

W2 gatewayctx supports bounded optional caller metadata tied to the asserted
subject/credential, with owned context copies and checked middleware parsing.
The full X-Gateway-* namespace is stripped, including reserved origin headers.
Parsing establishes no trust or permission; mTLS/network isolation is required.
Signed origin acceptance and producer activation are not included.

Audit events optionally carry caller/origin and operation/trace context. Owned
cloning and JSON/protobuf bindings preserve it; legacy omitted fields retain
their previous JSON bytes. EventFromProto is the common validated receiver
binding. Service receivers/storage must upgrade before producers use these fields.
The legacy local PostgresStore rejects caller-aware events explicitly; it cannot
silently discard their identity/correlation fields. Use upgraded central ingest.

## W1 token principal contract (source only)

caller.Identity is the shared versioned token-principal shape. Validate checks
structure, not authenticity or authority; issuer/registry bindings establish
caller kind. Legacy unregistered credentials remain unknown. Existing authntokens
responses accept optional identity without changing omitted legacy responses.
No gateway headers, token producers or runtime policies are activated here.

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
- `s3store.TokenObject` has optional UTC `expires_at` and stable
  `credential_id` for stored values. Missing expiry means unknown; descriptors
  retain grant lifetime. Providers inspect expiry; generic storage does not parse
  marketplace JWTs. Credential fingerprints must not be logged.
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


## Per-request router retry control (2026-11-07)

`stsclient.WithoutRouterRetry(ctx)` opts a request out of the shared router retry
transport. Finance uses it for WB task-create GET, which has upstream side effects.
Ordinary reads keep the existing retry budget. The marker survives request clones;
it does not guarantee upstream idempotency or suppress retries outside this package.

## Credential failure contract (November 14)

`apierror` publishes bounded allowlisted credential-plane failure codes for the
router's fail-closed HTTP 502 responses. Downstream verifiers may classify these
codes; they must not forward provider messages, references or credentials.
`tokenmint` provider 429 errors satisfy both ErrUpstream (existing transient retry
semantics) and ErrThrottled (quota classification). No new retry policy is added.
# Universal CSAR client prerequisites (November 15; source only)

csarclient wraps existing STS RouterClient/clientx for bounded relative-route JSON,
redirect/identity-header rejection and single-attempt worker calls. Protocol hints
are typed and bounded; optional short waits require explicit replay safety.
clientx keeps legacy conservative hints while exposing canonical header priority.
pgutil reader options centralize read-only session/default, min0 and server SQL
timeout setup. Existing pool defaults remain compatible. See csarclient/README.md.
No marketplace-specific transport, external credentials, deployed configuration
or SDK repository is added. Pending OZ08 retry/readiness commit is retained as
an explicit dependency; generic and downstream gates are required before merge.

## User Avatar Contract — 17 November 2026

authnconfig no longer exposes or validates the avatar-only StorageClient. Audit STS configuration and generic storage clients remain available to their owners.

## Redis coordination
- Generic Redis lock interfaces, owner-safe acquisition/release, renewable
  sessions, progress metadata and context helpers live in lock.
- redisutil owns the shared Redis client config/factory.
- These primitives were extracted from Aurum Core without changing lock keys,
  session JSON, error identity or the existing value-parameter public API.

The authntokens package defines the service-neutral router-to-issuer delegation
request and result. Exchange, discovery and resource consumption are bound to a
purpose, audience and scope. The resource owner supplies its catalog and mapping
to authorization tenants.

The universal csarclient also offers opt-in RetryHTTP429 for replay-safe reads
within an explicit short WaitBudget/MaxRetries. Default worker requests and
non-replayable mutations remain single-attempt.

STS and router HTTP clients reject all redirects before another request can carry
a signed assertion or service Bearer outside its configured endpoint. Universal
csarclient remains the bounded request layer for new owner adapters.
## Public HTTPS retrieval

`httpx/clientx.NewPublicHTTPClient` owns shared proxy-free, redirect-free HTTPS
transport for untrusted external endpoints. Every DNS result must be public;
the socket dials the checked IP while TLS authenticates the original hostname.
Private, special-use, translation and mixed public/private answers fail closed.
Callers own response-byte limits, admission and metadata/cache policy. Tokenmint
reuses this client unless its existing explicit AllowPrivate mode is selected.
No runtime configuration or network policy is activated by this library change.
`caller.ValidClientID` additionally accepts bounded HTTPS metadata-document URLs
without userinfo, queries or fragments; other identity references retain their
existing bound. Receivers need this Core version before enabling URL identifiers
that exceed the legacy reference syntax. Existing safe-reference IDs still pass.

## Generic OTP branding (source only, November 26)
- Email OTP defaults to a generic subject/body. Optional `email_otp.display_name`
  selects the product name separately from the sender header; HTML escapes both
  name and code. Configured subject stays exact. Production branding/config and
  transport behavior are unchanged by source preparation.

## Explicit identity policy receiver (source only, November 26)
- browser_directory defaults to subject-only UUID lookup. Providers, aliases and
  linked-identity projections are explicit bounded configuration; login enablement
  grants no directory visibility. Contact providers are excluded.
- identity_import is disabled by default; named importers bind exact service,
  source and provider authority, configured overrides and explicit write caps.
  Enabled import requires PostgreSQL, transactional audit and verified client TLS.
- LoadFromBytesWithIdentityPolicy is the matching full receiver; previous readers
  reject declarations. Both sections decode strictly. No deployment activation.

## Current per-profile owner admission — review preparation

Optional credential profile `admission` names an Authz decision profile, literal
resource reference and exact required granting scope. It is current authority,
independent of stored consent/data selection. Only
`LoadFromBytesWithProfileAdmission` opts into these declarations; older exported
loaders reject them even on a disabled declaration. Policy/namespace/resource/
scope fields are strictly validated, with no application defaults. The matching
Authn receiver enforces gates; this schema does not grant access itself. No DDL,
Redis/counter, signing-key or deployed configuration changes.
