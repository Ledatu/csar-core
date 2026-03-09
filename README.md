# csar-core

[![CI](https://github.com/Ledatu/csar-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Ledatu/csar-core/actions/workflows/ci.yml)

Shared Go primitives for the csar service family. Provides pluggable config sourcing, S3-compatible storage, Yandex Cloud IAM auth, and safe secret handling.

```
go get github.com/Ledatu/csar-core
```

Requires Go 1.25+.

---

## Packages

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

Objects are limited to 10 MB.

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
