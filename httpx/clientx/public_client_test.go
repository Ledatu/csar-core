package clientx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestPublicIP(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "0.0.0.0", "0.1.2.3", "10.1.2.3", "172.16.1.2", "192.168.1.2",
		"100.64.1.2", "169.254.169.254", "192.0.0.9", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "240.1.2.3",
		"::1", "::", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "fc00::1", "fe80::1%en0",
		"64:ff9b::a00:1", "2002:0a00:0001::1", "2001::1", "2001:db8::1", "3fff::1", "ff02::1",
	} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("accepted nonpublic address %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("rejected public address %s", raw)
		}
	}
}

func TestPublicDialerChecksEveryAddressAndPinsSocket(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []netip.Addr
		allowed   bool
	}{
		{"public", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, true},
		{"mapped public", []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1")}, true},
		{"mixed private", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, false},
		{"empty", nil, false},
		{"too many", make([]netip.Addr, 17), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups, calls := 0, 0
			sentinel := errors.New("socket reached")
			d := publicDialer{
				lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
					lookups++
					if network != "ip" || host != "client.example" {
						t.Fatal("unexpected lookup")
					}
					return tc.addresses, nil
				},
				dial: func(_ context.Context, _, address string) (net.Conn, error) {
					calls++
					if address != "1.1.1.1:443" {
						t.Fatalf("socket was not pinned: %s", address)
					}
					return nil, sentinel
				},
			}
			_, err := d.dialContext(t.Context(), "tcp", "client.example:443")
			if lookups != 1 || (calls == 1) != tc.allowed || tc.allowed && !errors.Is(err, sentinel) || !tc.allowed && !errors.Is(err, ErrNonPublicDestination) {
				t.Fatalf("lookups=%d calls=%d error=%v", lookups, calls, err)
			}
		})
	}
}

func TestPublicClientRejectsUnsafeRequestsBeforeNetwork(t *testing.T) {
	client := NewPublicHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	for _, raw := range []string{"http://example.com/a", "https://user:secret@example.com/a", "https://127.0.0.1/a", "https://[::ffff:127.0.0.1]/a", "https://169.254.169.254/a"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if response != nil {
			_ = response.Body.Close()
		}
		if !errors.Is(err, ErrNonPublicDestination) {
			t.Fatalf("unsafe destination accepted: %s: %v", raw, err)
		}
	}
	if client.Transport.(publicTransport).Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
	if !errors.Is(client.CheckRedirect(nil, nil), ErrNonPublicDestination) {
		t.Fatal("redirect accepted")
	}
}
