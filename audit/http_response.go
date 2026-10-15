package audit

import (
	"encoding/json"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/ledatu/csar-core/jsonredact"
)

const (
	HTTPResponseVersion  = 1
	MaxHTTPInspectBytes  = 64 << 10
	DefaultHTTPBodyBytes = 4 << 10
)

// HTTPResponse describes the final response sent to the caller, not every
// upstream retry or the business object's after-state. Body is always text.
type HTTPResponse struct {
	Version         int    `json:"version"`
	Status          int    `json:"status"`
	State           string `json:"state"`
	OmissionReason  string `json:"omission_reason,omitempty"`
	ContentType     string `json:"content_type,omitempty"`
	Origin          string `json:"origin"`
	Stage           string `json:"stage,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
	ObservedBytes   int64  `json:"observed_bytes"`
	CaptureComplete bool   `json:"capture_complete"`
	Code            string `json:"code,omitempty"`
	Message         string `json:"message,omitempty"`
	Body            string `json:"body,omitempty"`
	FieldsOmitted   bool   `json:"fields_omitted,omitempty"`
}

// HTTPResponseInput is bounded by the producer before normalization. Only a
// complete JSON error envelope is inspected; raw prefixes never become a fallback.
type HTTPResponseInput struct {
	Status          int
	ContentType     string
	ContentEncoding string
	Body            []byte
	ObservedBytes   int64
	Complete        bool
	MaxBodyBytes    int
	Secrets         []string
	Redact          jsonredact.Config
}

// CaptureHTTPResponse selects diagnostic envelope fields and sanitizes them
// before they can enter a queue. Arbitrary business payload fields are excluded.
func CaptureHTTPResponse(in *HTTPResponseInput) HTTPResponse {
	out := HTTPResponse{Version: HTTPResponseVersion, Status: in.Status, State: "omitted", Origin: "unknown", ObservedBytes: in.ObservedBytes, CaptureComplete: in.Complete}
	ct, _, err := mime.ParseMediaType(in.ContentType)
	if err == nil {
		out.ContentType = clipDiagnostic(ct, 128)
	}
	switch {
	case !in.Complete || len(in.Body) > MaxHTTPInspectBytes:
		out.OmissionReason = "inspection_limit"
		return out
	case in.ContentEncoding != "" && !strings.EqualFold(in.ContentEncoding, "identity"):
		out.OmissionReason = "content_encoding"
		return out
	case len(in.Body) == 0:
		out.State = "empty"
		return out
	case ct != "application/json" && !strings.HasSuffix(ct, "+json"):
		out.OmissionReason = "content_type"
		return out
	}
	// Always apply built-in sensitive keys, including when a route supplies
	// additional sensitive fields. RedactText also handles reflected credentials.
	redacted, err := jsonredact.ParseAndRedactJSON(in.Body, jsonredact.Config{PathFields: in.Redact.PathFields})
	if err == nil && len(in.Redact.SensitiveKeys) > 0 {
		redacted, err = jsonredact.ParseAndRedactJSON(redacted, in.Redact)
	}
	var object map[string]json.RawMessage
	if err != nil || json.Unmarshal(redacted, &object) != nil || object == nil {
		out.OmissionReason = "invalid_json_envelope"
		return out
	}
	safe, omitted := safeErrorFields(object, in.Secrets, 0)
	out.FieldsOmitted = omitted
	if len(safe) == 0 {
		out.OmissionReason = "no_error_fields"
		return out
	}
	out.Code = diagnosticString(safe, "code", "errorCode", "error_code", "error")
	out.Message = diagnosticString(safe, "message", "error_description", "detail", "title", "description", "reason")
	if nested, ok := safe["error"].(map[string]any); ok {
		if out.Code == "" {
			out.Code = diagnosticString(nested, "code", "errorCode", "error_code")
		}
		if out.Message == "" {
			out.Message = diagnosticString(nested, "message", "detail", "description", "reason")
		}
	}
	out.Code = clipDiagnostic(out.Code, 256)
	out.Message = clipDiagnostic(out.Message, 1024)
	body, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		out.OmissionReason = "encoding_error"
		return out
	}
	limit := in.MaxBodyBytes
	if limit <= 0 || limit > DefaultHTTPBodyBytes {
		limit = DefaultHTTPBodyBytes
	}
	out.State = "captured"
	out.Body = clipDiagnostic(string(body), limit)
	if len(body) > limit {
		out.State = "truncated"
	}
	return out
}

func safeErrorFields(object map[string]json.RawMessage, secrets []string, depth int) (map[string]any, bool) {
	out := make(map[string]any)
	omitted := false
	if depth > 4 {
		return out, true
	}
	for _, key := range []string{"code", "errorCode", "error_code", "error", "message", "error_description", "detail", "title", "description", "reason", "status", "request_id", "requestId"} {
		raw, ok := object[key]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			out[key] = clipDiagnostic(jsonredact.RedactText(value, secrets...), DefaultHTTPBodyBytes)
			continue
		}
		switch key {
		case "error":
			var nested map[string]json.RawMessage
			if json.Unmarshal(raw, &nested) == nil && nested != nil {
				fields, nestedOmitted := safeErrorFields(nested, secrets, depth+1)
				omitted = omitted || nestedOmitted
				if len(fields) > 0 {
					out[key] = fields
				}
			}
		case "status":
			var number int
			if json.Unmarshal(raw, &number) == nil {
				out[key] = number
			}
		}
	}
	return out, omitted || len(out) != len(object)
}

func diagnosticString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func clipDiagnostic(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

// EncodeHTTPMetadata keeps optional diagnostics from invalidating the existing
// 16 KiB ingest contract. It does not mutate the caller's metadata map.
func EncodeHTTPMetadata(base map[string]any, response *HTTPResponse) json.RawMessage {
	meta := make(map[string]any, len(base)+1)
	for key, value := range base {
		meta[key] = value
	}
	var bounded HTTPResponse
	if response != nil {
		bounded = *response
		meta["http_response"] = &bounded
	}
	encode := func() json.RawMessage {
		raw, err := json.Marshal(meta)
		if err != nil || len(raw) > MaxMetadataBytes {
			return nil
		}
		return raw
	}
	if raw := encode(); raw != nil {
		return raw
	}
	if response != nil {
		bounded.Body = ""
		bounded.State = "omitted"
		bounded.OmissionReason = "metadata_budget"
	}
	if raw := encode(); raw != nil {
		return raw
	}
	delete(meta, "query")
	meta["query_omitted"] = true
	if raw := encode(); raw != nil {
		return raw
	}
	for key := range meta {
		switch key {
		case "http_status", "audit_mode", "http_response", "query_omitted":
		default:
			delete(meta, key)
		}
	}
	return encode()
}
