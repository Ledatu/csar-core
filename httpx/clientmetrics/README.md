# Optional consuming-client metrics

`clientmetrics` observes the service's HTTP client; it does not change CSAR's
protocol, retry defaults, request headers, gzip negotiation, response limits,
TLS, cancellation, redirects or error values. Nothing is registered or enabled
by default.

```go
observer, err := clientmetrics.New(existingApplicationRegistry)
if err != nil { return err }
client = clientmetrics.WrapClient(client, observer, clientmetrics.ScopeRouter)
```

For STS-authenticated clients, `stsclient.NewRouterClientWithMetrics` installs
one outer router observer and a separate observer on token exchanges. Reusing
an observer or wrapping its client twice does not install another owned wrapper.
Unknown wrappers cannot be inspected: install this observer outside any custom
wrappers, once. The application registry must outlive its clients. HTTP response
bodies still must be closed; measurements are finalized once on Close (or
immediately for `http.NoBody`), after concurrent reads have returned. The recorded
lifecycle duration ends at the first EOF/read error, or at early Close if neither
was observed. A later caller drain is included in byte/read-time accounting.

## What the metrics mean

| Metric | Meaning |
|---|---|
| `csar_client_response_headers_duration_seconds` | RoundTrip until headers/error. Includes connection/TLS and auth/retry work inside its wrapper position; not provider-only time. |
| `csar_client_request_duration_seconds` | Start of the observed RoundTrip until EOF/read error/early close, including pauses between reads; not server latency. |
| `csar_client_body_read_duration_seconds` | Sum of time spent inside body Read calls, including Go's decompression; not pure network time or separate decompression CPU. |
| `csar_client_body_bytes` | Bytes actually consumed through the body, including caller drains. Partial/error/early-close results remain explicitly labelled. These exclude TLS/framing/headers and bodies drained inside an inner retry wrapper. |
| `csar_client_body_observations_total` | Whether `wire` and `decoded` representation byte counts were observable. An unknown representation gets no fake zero-byte histogram sample. |
| `csar_client_json_duration_seconds` | Shared `ReadAll` or `json.Unmarshal` duration, not business mapping/deduplication/database work. |
| `csar_client_json_buffer_bytes` | Bytes buffered by the shared JSON read before status/size validation, possibly partial or limit-plus-one. This is separate from the complete consumed/drained body, and does not mean accepted business data. |

Labels are bounded enums: scope (`router`, `sts`, `other`), standard method or
`OTHER`, HTTP status class, result, phase, completion, representation kind and
availability. URLs, paths, hosts, service/account identifiers, headers, secrets,
error messages and business models are never labels. ScopeRouter includes the
STS acquisition delay if needed, while ScopeSTS observes that exchange separately;
do not sum durations across both scopes as independent end-user work.

Representation availability follows the actual response at the wrapper:

- Identity response: consumed wire-representation and decoded bytes are known
  and equal.
- `Response.Uncompressed=true`: Go already decoded gzip. Decoded bytes are known;
  compressed wire bytes are unknown because the underlying transport consumed
  them. Neither Content-Length nor decoded size is substituted.
- Explicit still-encoded gzip/other response: consumed encoded bytes are known;
  decoded size is unknown until a decoder outside this observer consumes it.

This preserves Go's automatic decompression and the distinct explicit
Accept-Encoding behavior. Custom body-transforming transports must preserve
truthful response representation metadata; this package cannot reconstruct
bytes hidden beneath arbitrary wrappers. Counts are consumed representation
bytes, not complete TCP traffic, total bytes sent by the provider, or size of an
incomplete body's missing tail.

## JSON and service adoption

`clientx.DoJSON`/`DoJSONEmpty` automatically find the observer on their configured
client, including `http.DefaultClient` when Options.Client is nil. Existing size,
status, error and deferred drain behavior stays unchanged. A successful raw read
can still fail a later size/status/decode check.

Manual clients get transport/body observations when they share the instrumented
client. Their separate JSON phase needs the reusable helper:

```go
// Retain the caller's existing bound and cleanup.
raw, err := clientmetrics.ReadAll(client, io.LimitReader(resp.Body, limit+1))
// Retain existing status/limit checks before decoding.
err = clientmetrics.DecodeJSON(client, raw, &wireRows)
```

These helpers preserve io.ReadAll/json.Unmarshal semantics. Do not add a second
DecodeJSON around clientx's existing decode. If a caller subsequently decodes a
RawMessage into a second typed representation, that separate decode can be
observed deliberately; the metric records both actual decode calls. Business
model mapping and database transactions remain outside this package.

Aurum services can opt in once using the shared app option after adopting its
matching release; deployed binaries gain no instrumentation from publishing a
router manifest or updating Core source alone. No service restart or adoption is
performed by this library change.

Example checks:

```promql
rate(csar_client_json_buffer_bytes_sum{scope="router"}[5m])
rate(csar_client_json_duration_seconds_sum{scope="router",phase="decode"}[5m])
rate(csar_client_body_observations_total{scope="router",kind="wire",availability="unknown"}[5m])
```

Interpret sampling and workload mix alongside `go_memstats_alloc_bytes_total`,
GC pauses/cycles and existing AMQP handler metrics. Allocation counters include
all service work, not just JSON. Handler completions include continuations,
no-ops and other outcomes, not necessarily full marketplace syncs.
