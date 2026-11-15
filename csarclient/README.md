# Universal Go CSAR requests

`csarclient` supplies marketplace-neutral bounded requests over the existing
`stsclient.RouterClient.Client`. It reuses STS/TLS/token caching and `clientx`;
there is one authentication/request stack, no Ozon-specific shared transport.
Business adapters own endpoints, DTOs, units, pagination and source policy.

Construct with `New(Config{BaseURL, HTTPClient, Timeout, MaxRequestBytes,
MaxResponseBytes, Logger})`; execute `DoJSON[T](ctx, client, Request{Method,
Path, Body, Headers})`. Paths must stay relative to the configured authority;
redirects and reserved identity-header overrides are rejected. Default bounds
are 30 seconds and 1 MiB request/response; explicit limits may not exceed 64 MiB.

Default worker mode performs one attempt, suppressing lower STS transport retries.
The typed clientx error preserves safe CSAR status and bounded retry timing.
The worker can persist cooldown and return scheduling to AMQP without sleeping
under a Redis heartbeat. No arbitrary POST or supplied idempotency header proves
safe replay, and the client never creates provider credentials/idempotency keys.

Explicit `WaitBudget` (at most 5 seconds), `MaxRetries` (at most 3) AND per-request
`ReplaySafe` enable short synchronous waits only for marked throttled/backpressure
503 responses. Circuits, unknown/unmarked 503s, network ambiguity and unrelated
statuses are returned. Timing priority follows X-CSAR-Wait-MS, Retry-After, then
the validated envelope hint. Context bounds all attempts and waits. This is not a
claim of complete TS/Python feature parity or a public standalone SDK release.

`pgutil.WithReadOnly`, `WithMinConns(0)` and `WithStatementTimeout` let callers
configure explicit bounded reader pools without copied runtime-param setup.
Read-only sessions do not prove SELECT-only role grants; deployed least privilege
and native SPQR behavior remain release acceptance.
