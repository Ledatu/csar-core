package postbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/ycloud"
)

type fakeTokenResolver struct {
	token string
	err   error
}

func (r fakeTokenResolver) ResolveToken(context.Context) (string, error) {
	return r.token, r.err
}

func TestSendEmail(t *testing.T) {
	var gotAuth string
	var gotReq sendEmailRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/email/outbound-emails" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("X-YaCloud-SubjectToken")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClientWithResolver(&Config{Endpoint: srv.URL}, srv.Client(), fakeTokenResolver{token: "iam-token"})
	err := client.SendEmail(context.Background(), &Message{
		FromEmailAddress: `"AURUMSKYNET ID" <login@example.com>`,
		ToAddresses:      []string{"user@example.com"},
		Subject:          "Your code",
		TextBody:         "text body",
		HTMLBody:         "<p>html body</p>",
	})
	if err != nil {
		t.Fatalf("SendEmail() error = %v", err)
	}
	if gotAuth != "iam-token" {
		t.Fatalf("X-YaCloud-SubjectToken = %q, want iam-token", gotAuth)
	}
	if gotReq.FromEmailAddress != `"AURUMSKYNET ID" <login@example.com>` {
		t.Fatalf("FromEmailAddress = %q", gotReq.FromEmailAddress)
	}
	if len(gotReq.Destination.ToAddresses) != 1 || gotReq.Destination.ToAddresses[0] != "user@example.com" {
		t.Fatalf("unexpected destination: %#v", gotReq.Destination.ToAddresses)
	}
	if gotReq.Content.Simple.Subject.Data != "Your code" {
		t.Fatalf("subject = %q", gotReq.Content.Simple.Subject.Data)
	}
	if gotReq.Content.Simple.Body.Text.Data != "text body" {
		t.Fatalf("text body = %q", gotReq.Content.Simple.Body.Text.Data)
	}
	if gotReq.Content.Simple.Body.HTML.Data != "<p>html body</p>" {
		t.Fatalf("HTML body = %q", gotReq.Content.Simple.Body.HTML.Data)
	}
	if gotReq.Content.Simple.Subject.Charset != defaultCharset {
		t.Fatalf("charset = %q, want %q", gotReq.Content.Simple.Subject.Charset, defaultCharset)
	}
}

func TestSendEmailHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rejected", http.StatusForbidden)
	}))
	defer srv.Close()

	client := NewClientWithResolver(&Config{Endpoint: srv.URL}, srv.Client(), fakeTokenResolver{token: "iam-token"})
	if err := client.SendEmail(context.Background(), &Message{
		FromEmailAddress: "login@example.com",
		ToAddresses:      []string{"user@example.com"},
		Subject:          "Your code",
		TextBody:         "text body",
	}); err == nil {
		t.Fatal("expected HTTP error")
	}
}

func TestConfigDefaultsAndValidate(t *testing.T) {
	cfg := &Config{
		Auth: authConfigForTest("metadata"),
	}
	cfg.ApplyDefaults()
	if cfg.Endpoint != DefaultEndpoint {
		t.Fatalf("Endpoint = %q, want %q", cfg.Endpoint, DefaultEndpoint)
	}
	if cfg.Region != DefaultRegion {
		t.Fatalf("Region = %q, want %q", cfg.Region, DefaultRegion)
	}
	if err := cfg.Validate("postbox"); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateRequiresAuthMode(t *testing.T) {
	cfg := Config{Endpoint: DefaultEndpoint, Region: DefaultRegion}
	if err := cfg.Validate("postbox"); err == nil {
		t.Fatal("expected auth_mode validation error")
	}
}

func authConfigForTest(mode string) ycloud.AuthConfig {
	return ycloud.AuthConfig{AuthMode: mode}
}
