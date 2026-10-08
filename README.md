# csar-core

[![CI](https://github.com/ledatu/csar-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ledatu/csar-core/actions/workflows/ci.yml)

Shared Go primitives for the csar service family. Provides pluggable config sourcing, PostgreSQL utilities, router-bound STS clients, HTTP helpers, S3-compatible storage, Yandex Cloud IAM auth, and safe secret handling.

```
go get github.com/ledatu/csar-core
```

Requires Go 1.25+.

---

## Packages

### `pgutil` — PostgreSQL connection pool, migrations, and helpers

Shared database primitives used by csar-authn, csar-authz, and other services.

```go
pool, err := pgutil.NewPool(ctx, dsn,
    pgutil.WithLogger(logger),
    pgutil.WithMaxConns(10),
)

err = pgutil.RunMigrations(ctx, pool, "my_schema_migrations", migrations, logger)

err = pgutil.WithTx(ctx, pool, func(tx pgx.Tx) error {
    _, err := tx.Exec(ctx, "INSERT INTO ...")
    return err
})

if pgutil.IsNotFound(err) { /* handle missing row */ }
if pgutil.IsDuplicateKey(err) { /* handle conflict */ }
```

| Function | Purpose |
|---|---|
| `NewPool` | Creates a pgxpool with functional options, pings to verify |
| `RunMigrations` | Forward-only migration runner with per-service tracking tables |
| `WithTx` | Executes a function in a transaction (auto rollback/commit) |
| `IsNotFound` | Checks for `pgx.ErrNoRows` |
| `IsDuplicateKey` | Checks for PostgreSQL unique constraint violation (23505) |

---

### `configsource` — Pluggable config loading with integrity validation

Polls an external config source on an interval, validates content integrity via SHA-256, and calls your apply function only when something changes.

```go
src := configsource.NewHTTPSource("https://example.com/config.yaml", nil, nil)

watcher := configsource.NewConfigWatcher(src, func(ctx context.Context, data []byte) (bool, error) {
    return true, yaml.Unmarshal(data, &myCfg)
}, slog.Default())

go watcher.RunPeriodicWatch(ctx, 30*time.Second)
```

**Sources**

| Source | Constructor | ETag strategy |
|---|---|---|
| File | `NewFileSource(path)` | `mtime` + `size` |
| HTTP(S) | `NewHTTPSource(url, headers, client)` | `ETag` / `Last-Modified` |
| S3-compatible | `NewS3Source(client, key)` | S3 object ETag |

**Hash policies**

| Policy | Behaviour |
|---|---|
| `HashTOFU` (default) | Trusts the first fetch; rejects same-ETag content changes (tampering detection) |
| `HashPinned` | Validates every fetch against an operator-supplied SHA-256 |
| `HashDisabled` | No hash checking |

```go
// Pinned hash example
watcher := configsource.NewConfigWatcher(src, applyFn, logger,
    configsource.WithHashPolicy(configsource.HashPinned),
    configsource.WithPinnedHash("a3f1..."),
)
```

---

### `httpx` — HTTP JSON and query helpers

Shared request/response helpers used by router-facing services.

```go
limit, err := httpx.ParseLimit(r, 1000, 100000)
active, err := httpx.OptionalBool(r.URL.Query().Get("active"))
ids, err := httpx.ParseInt64List(httpx.Values(r.URL.Query()["nm_id"]))
httpx.WriteJSON(w, http.StatusOK, payload)
```

`httpx/clientx` is the outbound JSON client helper for service-to-service calls
through the router. It enforces response size caps, optional timeouts, typed
non-2xx errors, and capped error-body logging.

---

### `stsclient` — Router-bound service authentication

Builds HTTP clients that exchange service assertions through STS and attach
Bearer tokens on router-bound requests. The router transport retries transient
or retryable idempotent calls with bounded jittered retries.

```go
client, err := stsclient.NewRouterClient(&stsclient.ServiceAuthConfig{
    RouterBaseURL: "https://csar:8443",
    STSEndpoint:   "https://authn:8081/sts/token",
    Audience:      "csar-authz-svc",
    ServiceName:   "svc:example",
}, logger)
```

---

### `s3store` — S3-compatible object storage client

Supports Yandex Cloud Object Storage (and any S3-compatible backend). Two auth modes: static AWS Sig V4 keys, or Yandex Cloud IAM tokens.

```go
client, err := s3store.NewClient(&s3store.Config{
    Bucket:   "my-bucket",
    Endpoint: "https://storage.yandexcloud.net",
    Region:   "ru-central1",
    Prefix:   "tokens/",
    Auth: ycloud.AuthConfig{
        AuthMode:        "static",
        AccessKeyID:     secret.NewSecret(os.Getenv("S3_KEY_ID")),
        SecretAccessKey: secret.NewSecret(os.Getenv("S3_SECRET")),
    },
}, slog.Default())

obj, err := client.GetObject(ctx, "tokens/my-token")
err = client.PutObject(ctx, "tokens/my-token", data)
err = client.DeleteObject(ctx, "tokens/my-token")
entries, err := client.ListObjects(ctx)
```

The legacy materialized object APIs are limited to 10 MB. Bounded streaming
APIs support objects up to 64MiB with a 30s operation deadline:

- `PutStream` requires an immutable seekable body and its exact byte size,
  returning an object/version receipt.
- `PutStreamIfAbsent` adds `If-None-Match: *`; `ErrObjectExists` permits HEAD
  through `StatStreamObject`, followed by content verification of that version.
- `OpenVersion` requires a real version ID and caller-selected byte cap. It
  rejects providers that return another version or exceed the cap. Close the
  reader to release its request context.

These APIs join validated prefixes and keys, support existing static/IAM auth
and reject IAM redirects. Version receipts and ETags are not content integrity
proof: archive callers must verify complete downloaded bytes themselves. Verify
the actual store's versioning and conditional-write support before activation.

---

### `audit` — Event identity, router transport and PostgreSQL outbox

`PrepareEvent` owns payloads and establishes a stable UUID/microsecond timestamp.
Retain that prepared identity across manual retries. `NewRouterClient` provides
existing asynchronous best-effort delivery; `NewRouterTransport` is synchronous
and is the transport required for durable outbox acceptance.

`NewPGOutbox(pool, service)` creates a service-scoped relay. Run `Migrate` once
at startup, then call `EnqueueTx` in the same transaction as the business write.
An enqueue error must roll back the transaction. `StartRouterRelay` wires the
configured STS transport, worker and Prometheus backlog collectors, returning
an idempotent stop/join function. Release it before closing the pool.

Claim tokens fence 60s leases; sends have30s deadlines and failures retain the
same event for retry. Accepted delivery removes only the pending copy. An
uncertain receipt can replay an event, so receiving services must preserve IDs
and deduplicate exact contents. This does not make uncovered producer mutations
transactional. Authn/authz enablement is startup-only and defaults to false.

Backlog metrics expose count/oldest age and scrape success; a failed DB query
does not report a false zero. Tests use an isolated localhost PostgreSQL database
named `csar_audit_test`; never point the integration fixture at production.

---

### `ycloud` — Yandex Cloud IAM token resolver

Resolves and caches IAM tokens with automatic refresh. Safe for concurrent use.

```go
resolver, err := ycloud.NewIAMTokenResolver(&ycloud.AuthConfig{
    AuthMode: "service_account",
    SAKeyFile: "/etc/csar/sa-key.json",
}, slog.Default())

token, err := resolver.Token(ctx) // cached; refreshes automatically
```

**Auth modes**

| Mode | Description |
|---|---|
| `iam_token` | Static IAM token (dev/testing) |
| `oauth_token` | Yandex OAuth token, exchanged for IAM at runtime |
| `metadata` | Instance metadata service (compute VMs) |
| `service_account` | JWT-based auth via service account key file |

---

### `secret` — Self-redacting secret type

Wraps sensitive strings so they never leak into logs or serialized output.

```go
type Config struct {
    APIKey secret.Secret `yaml:"api_key"`
}

cfg.APIKey = secret.NewSecret(rawKey)

logger.Info("loaded", "key", cfg.APIKey) // → key=[REDACTED]
fmt.Println(cfg.APIKey)                  // → [REDACTED]
json.Marshal(cfg)                        // → {"api_key":"[REDACTED]"}

cfg.APIKey.Plaintext()                   // → actual value
```

Implements `fmt.Stringer`, `fmt.GoStringer`, `slog.LogValuer`, and `encoding.TextMarshaler` — all return `[REDACTED]`.

---

## License

MIT
