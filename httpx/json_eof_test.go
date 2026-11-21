package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONRejectsEveryTrailingToken(t *testing.T) {
	for _, suffix := range []string{"]", "}", "{}", "[]", "null", "true", "42", "garbage", "/* comment */"} {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":1}`+suffix))
		var out struct {
			Value int `json:"value"`
		}
		if err := ReadJSON(req, &out); err == nil {
			t.Fatalf("accepted trailing %q", suffix)
		}
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"value\":1}\n \t"))
	var out struct {
		Value int `json:"value"`
	}
	if err := ReadJSON(req, &out); err != nil || out.Value != 1 {
		t.Fatal(out, err)
	}
}
