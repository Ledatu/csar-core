package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/jsonredact"
)

func gzipDiagnostic(t *testing.T, body, extra string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if extra != "" {
		zw.Extra = []byte(extra)
	}
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestHTTPResponseGzipSanitization(t *testing.T) {
	body := gzipDiagnostic(t, `{"error":{"code":"denied","message":"Bearer privatecredential known-secret user@example.com"},"password":"hidden","detail":"route-private","business":"private"}`, "")
	before := bytes.Clone(body)
	r := CaptureHTTPResponse(&HTTPResponseInput{
		Status: 503, ContentType: "application/problem+json", ContentEncoding: " GZip ",
		Body: body, Complete: true, ObservedBytes: int64(len(body)), Secrets: []string{"known-secret"},
		Redact: jsonredact.Config{PathFields: []string{"detail"}},
	})
	if r.State != "captured" || r.Code != "denied" || !r.CaptureComplete || r.ObservedBytes != int64(len(body)) || !r.FieldsOmitted {
		t.Fatalf("response=%+v", r)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"privatecredential", "known-secret", "user@example.com", "hidden", "route-private", `"business"`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("leaked %q", secret)
		}
	}
	if !bytes.Equal(body, before) {
		t.Fatal("mutated forwarded representation")
	}
}

func TestHTTPResponseGzipIntegrityAndLimits(t *testing.T) {
	jsonBody := `{"message":"unavailable"}`
	valid := gzipDiagnostic(t, jsonBody, "")
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 1
	members := append(gzipDiagnostic(t, `{"message":`, ""), gzipDiagnostic(t, `"unavailable"}`, "")...)
	badMember := append(bytes.Clone(valid), corrupt...)
	exactJSON := jsonBody + strings.Repeat(" ", MaxHTTPInspectBytes-len(jsonBody))
	exactEncoded := gzipDiagnostic(t, jsonBody, strings.Repeat("x", MaxHTTPInspectBytes-len(valid)-2))
	if len(exactEncoded) != MaxHTTPInspectBytes {
		t.Fatal("invalid boundary fixture")
	}
	for _, tc := range []struct {
		name, encoding, state, reason string
		body                          []byte
		complete                      bool
	}{
		{"valid", "gzip", "captured", "", valid, true},
		{"multiple members", "gzip", "captured", "", members, true},
		{"decoded boundary", "gzip", "captured", "", gzipDiagnostic(t, exactJSON, ""), true},
		{"encoded boundary", "gzip", "captured", "", exactEncoded, true},
		{"encoded overflow", "gzip", "omitted", "inspection_limit", gzipDiagnostic(t, jsonBody, strings.Repeat("x", MaxHTTPInspectBytes-len(valid)-1)), true},
		{"decoded overflow", "gzip", "omitted", "inspection_limit", gzipDiagnostic(t, exactJSON+" ", ""), true},
		{"expansion bomb", "gzip", "omitted", "inspection_limit", gzipDiagnostic(t, jsonBody+strings.Repeat(" ", MaxHTTPInspectBytes*16), ""), true},
		{"checksum", "gzip", "omitted", "invalid_gzip", corrupt, true},
		{"truncated trailer", "gzip", "omitted", "invalid_gzip", valid[:len(valid)-1], true},
		{"trailing garbage", "gzip", "omitted", "invalid_gzip", append(bytes.Clone(valid), []byte("garbage")...), true},
		{"corrupt later member", "gzip", "omitted", "invalid_gzip", badMember, true},
		{"incomplete capture", "gzip", "omitted", "inspection_limit", valid, false},
		{"invalid JSON", "gzip", "omitted", "invalid_json_envelope", gzipDiagnostic(t, jsonBody+"x", ""), true},
		{"unsupported encoding", "br", "omitted", "content_encoding", valid, true},
		{"stacked encoding", "gzip, gzip", "omitted", "content_encoding", valid, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := CaptureHTTPResponse(&HTTPResponseInput{Status: 503, ContentType: "application/json", ContentEncoding: tc.encoding, Body: tc.body, Complete: tc.complete})
			if r.State != tc.state || r.OmissionReason != tc.reason {
				t.Fatalf("response=%+v", r)
			}
			if tc.state == "omitted" && (r.Body != "" || r.Code != "" || r.Message != "") {
				t.Fatal("stored a raw or unvalidated prefix")
			}
		})
	}
}
