package jsonredact

import (
	"encoding/json"
	"testing"
)

func TestParseAndRedactJSON(t *testing.T) {
	raw := []byte(`{"password":"secret","user":{"token":"abc"}}`)
	out, err := ParseAndRedactJSON(raw, Config{Mask: "***"})
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["password"] != "***" {
		t.Fatalf("password = %v", m["password"])
	}
	user := m["user"].(map[string]any)
	if user["token"] != "***" {
		t.Fatalf("token = %v", user["token"])
	}
}

func TestRedactPathWildcard(t *testing.T) {
	var data any
	_ = json.Unmarshal([]byte(`{"users":[{"email":"a@x.com"},{"email":"b@x.com"}]}`), &data)
	if !RedactPath(data, []string{"users", "*", "email"}, "X") {
		t.Fatal("expected redaction")
	}
	out, _ := json.Marshal(data)
	if string(out) != `{"users":[{"email":"X"},{"email":"X"}]}` {
		t.Fatalf("got %s", out)
	}
}

func TestRedactQueryMap(t *testing.T) {
	q := map[string]string{"campaignId": "1", "token": "abc"}
	RedactQueryMap(q, "[REDACTED]")
	if q["token"] != "[REDACTED]" {
		t.Fatalf("token = %q", q["token"])
	}
	if q["campaignId"] != "1" {
		t.Fatalf("campaignId = %q", q["campaignId"])
	}
}

func TestRedactQueryMapExtraKeys(t *testing.T) {
	q := map[string]string{"campaignId": "1", "wbToken": "secret"}
	RedactQueryMap(q, "[REDACTED]", "wbToken", "apiKey")
	if q["wbToken"] != "[REDACTED]" {
		t.Fatalf("wbToken = %q", q["wbToken"])
	}
	if q["campaignId"] != "1" {
		t.Fatalf("campaignId = %q", q["campaignId"])
	}
}
