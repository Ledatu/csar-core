package clientx

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrNonPublicDestination means the request cannot be sent to a public HTTPS
// destination. It deliberately excludes the URL, DNS results and credentials.
var ErrNonPublicDestination = errors.New("clientx: public HTTPS destination required")

// NewPublicHTTPClient returns a client for untrusted public HTTPS endpoints.
// It disables environment proxies and redirects, checks every resolved address,
// then dials the checked IP directly. TLS still authenticates the original host.
// Callers must bound response bytes and concurrent work; CloseIdleConnections
// releases the client's connection pool. A nonpositive timeout uses three seconds.
func NewPublicHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	dial := publicDialer{lookup: net.DefaultResolver.LookupNetIP, dial: dialer.DialContext}
	transport := &http.Transport{
		DialContext:       dial.dialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 4,
		MaxConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Timeout: timeout, Transport: publicTransport{transport},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return ErrNonPublicDestination
		},
	}
}

type publicTransport struct{ *http.Transport }

func (t publicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.Scheme != "https" || r.URL.Hostname() == "" || r.URL.User != nil ||
		r.URL.Opaque != "" || r.Host != "" && r.Host != r.URL.Host {
		return nil, ErrNonPublicDestination
	}
	return t.Transport.RoundTrip(r)
}

type publicDialer struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (d publicDialer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrNonPublicDestination
	}
	ips, err := d.lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 || len(ips) > 16 {
		return nil, ErrNonPublicDestination
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, ErrNonPublicDestination
		}
	}
	// Never resolve the name again after checking it. A later connection performs
	// a new check, so DNS rebinding cannot change the checked socket destination.
	return d.dial(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

var nonPublicNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" || !addr.IsGlobalUnicast() ||
		CheckInternalIP(net.IP(addr.AsSlice()), AllInternalIPClasses()) != nil {
		return false
	}
	// IPv6 special/translation spaces must not tunnel a disallowed IPv4 target.
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(addr) {
			return false
		}
	}
	return true
}
