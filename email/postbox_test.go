package email

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"testing"

	"github.com/ledatu/csar-core/postbox"
)

type tokenResolver struct{}

func (tokenResolver) ResolveToken(context.Context) (string, error) { return "test-token", nil }

func TestPostboxAdapterPreservesMessage(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"MessageId":"provider-receipt"}`))
	}))
	defer srv.Close()
	sender := &postboxSender{client: postbox.NewClientWithResolver(&postbox.Config{Endpoint: srv.URL}, srv.Client(), tokenResolver{})}
	receipt, err := sender.Send(context.Background(), exampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	from, parseErr := mail.ParseAddress(got["FromEmailAddress"].(string))
	if parseErr != nil || from.Name != "Отправитель" || from.Address != "sender@example.com" {
		t.Fatal("sender changed")
	}
	if receipt.Provider != ProviderPostbox || receipt.MessageID != "provider-receipt" {
		t.Fatalf("unexpected submission: %+v", receipt)
	}
}
