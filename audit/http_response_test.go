package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ledatu/csar-core/jsonredact"
)

func TestHTTPResponseSanitization(t *testing.T) {
	body := []byte(`{"error":{"code":"denied","message":"Bearer abcdefghijk password=badsecret email user@example.com reflected-super-secret"},"token":"do-not-store","customer":{"name":"private"}}`)
	r := CaptureHTTPResponse(&HTTPResponseInput{Status: 403, ContentType: "application/json; charset=utf-8", Body: body, Complete: true, Secrets: []string{"reflected-super-secret"}, Redact: jsonredact.Config{SensitiveKeys: []string{"extra"}}})
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"abcdefghijk", "badsecret", "user@example.com", "reflected-super-secret", "do-not-store", "private"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if r.Code != "denied" || r.State != "captured" || !r.FieldsOmitted {
		t.Fatalf("response: %+v", r)
	}
}

func TestHTTPResponseOmissionsAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name, ct, encoding, body, reason, state string
		complete                                bool
	}{
		{"empty", "", "", "", "", "empty", true},
		{"html", "text/html", "", "<html>secret</html>", "content_type", "omitted", true},
		{"invalid", "application/json", "", `{"password":"`, "invalid_json_envelope", "omitted", true},
		{"partial", "application/json", "", `{"message":"password=abc`, "inspection_limit", "omitted", false},
		{"gzip", "application/json", "gzip", "bytes", "content_encoding", "omitted", true},
		{"business", "application/json", "", `{"customer":"private"}`, "no_error_fields", "omitted", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := CaptureHTTPResponse(&HTTPResponseInput{ContentType: tc.ct, ContentEncoding: tc.encoding, Body: []byte(tc.body), Complete: tc.complete})
			if r.State != tc.state || r.OmissionReason != tc.reason || r.Body != "" {
				t.Fatalf("%+v", r)
			}
		})
	}
	r := CaptureHTTPResponse(&HTTPResponseInput{ContentType: "application/problem+json", Body: []byte(`{"detail":"` + strings.Repeat("я", 3000) + `"}`), Complete: true, MaxBodyBytes: 33})
	if r.State != "truncated" || len(r.Body) > 33 || !utf8.ValidString(r.Body) {
		t.Fatalf("invalid truncated response: %+v", r)
	}
	raw := EncodeHTTPMetadata(map[string]any{"http_status": 503, "query": strings.Repeat("q", 20000), "route": strings.Repeat("r", 20000)}, &r)
	if !json.Valid(raw) || len(raw) > MaxMetadataBytes {
		t.Fatalf("metadata bytes=%d", len(raw))
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["http_status"] != float64(503) || fields["http_response"] == nil {
		t.Fatal("lost basic event")
	}
}

func TestHTTPResponseNestedOmissions(t *testing.T) {
	r := CaptureHTTPResponse(&HTTPResponseInput{ContentType: "application/json", Complete: true, Body: []byte(`{"error":{"message":"Unavailable","customers":[{"email":"private@example.com"}]}}`)})
	if !r.FieldsOmitted || strings.Contains(r.Body, "customers") {
		t.Fatal("nested private fields must be omitted and declared")
	}
}
