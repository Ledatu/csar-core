package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadStrictJSONSecurityObjects(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate":          `{"subject":"a","subject":"b"}`,
		"case alias":         `{"subject":"a","Subject":"b"}`,
		"escaped alias":      `{"subject":"a","\u0073ubject":"b"}`,
		"nested":             `{"items":[{"id":"a","ID":"b"}]}`,
		"unicode fold":       `{"items":[{"k":"a","K":"b"}]}`,
		"invalid UTF8":       "{\"subject\":\"\xff\"}",
		"unknown field":      `{"unexpected":"credential-value"}`,
		"trailing":           `{"subject":"a"} {}`,
		"trailing delimiter": `{"subject":"a"}]`,
		"array":              `[]`,
		"null":               `null`,
		"depth":              `{"items":` + strings.Repeat("[", 64) + `0` + strings.Repeat("]", 64) + `}`,
		"bytes":              `{"subject":"` + strings.Repeat("x", maxReadJSONBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out struct {
				Subject string              `json:"subject"`
				Items   []map[string]string `json:"items"`
			}
			err := ReadStrictJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &out)
			if err == nil {
				t.Fatal("ambiguous security request accepted")
			}
			if strings.Contains(err.Error(), "credential-value") {
				t.Fatal("request value leaked")
			}
		})
	}
	var out struct {
		Subject string              `json:"subject"`
		Items   []map[string]string `json:"items"`
	}
	if err := ReadStrictJSON(httptest.NewRequest("POST", "/", strings.NewReader(`{"subject":"café","items":[{"id":"one"},{"id":"two"}]} `)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != "café" || len(out.Items) != 2 {
		t.Fatal("valid request lost")
	}
	// The existing decoder's treatment of old clients is intentionally unchanged.
	if err := ReadJSON(httptest.NewRequest("POST", "/", strings.NewReader(`{"subject":"a","subject":"b"}`)), &out); err != nil || out.Subject != "b" {
		t.Fatal("legacy JSON behavior changed", err)
	}
}
