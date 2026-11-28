# Bounded element-streaming JSON

Use `jsonstream.DecodeObject(reader, maxDecodedBytes, fields)` to decode selected
arrays one element at a time. The complete typed page is returned only after JSON,
trailing whitespace, the decoded-byte limit and reader/gzip integrity checks pass.
Any failure returns zero output. No database writes or progress callbacks occur.

```go
page, info, err := jsonstream.DecodeObject(body, maxDecodedBytes,
    func(out *Page) []jsonstream.Field {
        return []jsonstream.Field{
            jsonstream.Array("items", &out.Items),
            jsonstream.Value("cursor", &out.Cursor),
        }
    })
```

For HTTP use `clientx.DoJSONStream(ctx, req, opts, fields)`. It shares the buffered
client's transport, timeout, status handling, bounded diagnostics, error envelope,
retry timing/provenance and cleanup. Existing `DoJSON` stays buffered. For custom
HTTP adapters use `clientmetrics.DecodeObject` to observe the same decoder.
Neither entrypoint adds request retries or changes the CSAR wire protocol.

Limits and compatibility:

- A positive limit (less than MaxInt64) applies to the representation delivered
  by the reader, normally decoded JSON after Go HTTP automatic decompression.
  Read failures win over oversize, then JSON failures. Prefix is bounded to 4KiB
  and omitted on oversize. Info.ReadError retains the original reader error.
- Whole-input nesting is limited to 10,000, including envelope/array levels.
  Incomplete JSON returns SyntaxError. Trailing values/garbage are rejected.
- Typed slices, strings and RawMessage fields remain materialized. A record,
  Value field or unknown field may still require a large encoded buffer. This
  is not constant-memory decoding for arbitrary JSON. Do not replace Array with
  a single Decoder.Decode of the whole page: it buffers the complete value.
- Field declarations explicitly describe a plain object DTO, with unique names
  under case folding. Standard null/empty/duplicate-field slice reuse and value
  decoding apply. Embedded field resolution or a custom top-level unmarshaller
  is not inferred; use the existing buffered API for those shapes.
- Field/element custom unmarshallers must be pure DTO transformations. They can
  execute before a later syntax error. Always keep business effects after a
  successful whole-page return and owner validation.
- JSON error classes are preserved for syntax/type failures. Per-value parser
  offsets, field context and diagnostic wording can differ from whole-document
  Unmarshal. The HTTP Error envelope and CSAR v1 response contract are unchanged;
  callers must not parse decoder error strings as a machine protocol.

Streaming metrics use separate `csar_client_json_stream_duration_seconds` and
`csar_client_json_stream_bytes` families. Duration combines input waits and parse
work, excluding later business/DB work. Bytes describe the supplied reader, normally decoded JSON after automatic
decompression, and include partial reads and the limit-plus-one sentinel: they are not retained heap, accepted data or compressed
wire size. No old buffered-read/Unmarshal metric is emitted for this operation.
