package origincontext

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/csarclient"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/stsclient"
)

type gatewayParentKey struct{}
type gatewayParent struct {
	token, resource string
	expires         time.Time
}

// WithGatewayParent adopts an opaque parent only from an already trusted gateway
// request. The service must enforce mTLS/network isolation on that ingress.
// Authn validates its signature and addressed service when issuing the child;
// this helper never treats backend header parsing as signature verification.
func WithGatewayParent(ctx context.Context, incoming *http.Request) (context.Context, error) {
	if incoming == nil {
		return nil, ErrInvalid
	}
	id, err := gatewayctx.FromRequestChecked(incoming)
	if err != nil || id.Origin == nil || !time.Now().Before(id.Origin.ExpiresAt) || id.Tenant == "" || !caller.ValidReference(id.Tenant) {
		return nil, ErrInvalid
	}
	var values []string
	for name, items := range incoming.Header {
		if strings.EqualFold(name, HeaderForwardedAuthorization) {
			values = append(values, items...)
		}
	}
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, ErrInvalid
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) > MaxTokenBytes || strings.ContainsAny(token, " \t\r\n") {
		return nil, ErrInvalid
	}
	return context.WithValue(ctx, gatewayParentKey{}, gatewayParent{token: token, resource: id.Tenant, expires: id.Origin.ExpiresAt}), nil
}

// DelegateClient reuses an existing authenticated STS router client. It owns no
// STS cache and never places request-specific origin credentials in that cache.
type DelegateClient struct {
	base   *url.URL
	http   *http.Client
	issuer *csarclient.Client
}

func NewDelegateClient(routerBaseURL string, authenticated *http.Client) (*DelegateClient, error) {
	u, err := url.Parse(routerBaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || authenticated == nil || authenticated.Jar != nil {
		return nil, ErrInvalid
	}
	issuer, err := csarclient.New(csarclient.Config{BaseURL: routerBaseURL, HTTPClient: authenticated, Timeout: 5 * time.Second, MaxRequestBytes: 16 << 10, MaxResponseBytes: 16 << 10})
	if err != nil {
		return nil, ErrInvalid
	}
	return &DelegateClient{base: u, http: authenticated, issuer: issuer}, nil
}

// Client returns a receiver-bound client. Every dispatch obtains a fresh child
// bound to the actual method/URI/body; missing or expired parents fail closed.
// Redirects and automatic STS router retries are disabled for these requests.
func (c *DelegateClient) Client(receiver string) (*http.Client, error) {
	if c == nil || receiver == "" || !caller.ValidReference(receiver) {
		return nil, ErrInvalid
	}
	client := *c.http
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &delegateTransport{client: c, base: base, receiver: receiver}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}

type delegateTransport struct {
	client   *DelegateClient
	base     http.RoundTripper
	receiver string
}

func (t *delegateTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	// RoundTripper owns the body, including failures before an upstream dispatch.
	handedOff := false
	defer func() {
		if !handedOff && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	p, ok := req.Context().Value(gatewayParentKey{}).(gatewayParent)
	u := req.URL
	prefix := strings.TrimRight(t.client.base.Path, "/") + "/"
	if !ok || !time.Now().Before(p.expires) || u == nil || u.Scheme != t.client.base.Scheme || !strings.EqualFold(u.Host, t.client.base.Host) || u.User != nil || u.Opaque != "" || u.Fragment != "" || req.RequestURI != "" || !strings.HasPrefix(u.Path, prefix) {
		return nil, ErrInvalid
	}
	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-gateway-") || strings.EqualFold(name, HeaderAuthorization) {
			return nil, ErrInvalid
		}
	}
	ctx, cancel := context.WithDeadline(stsclient.WithoutRouterRetry(req.Context()), p.expires)
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	out := req.Clone(ctx)
	hash, err := RequestHash(out)
	if err != nil {
		return nil, ErrInvalid
	}
	result, callErr := csarclient.DoJSON[Response](ctx, t.client.issuer, csarclient.Request{Method: http.MethodPost, Path: "/svc/authn/origin-context/delegate", Body: &DelegateRequest{ParentToken: p.token, Receiver: t.receiver, Resource: p.resource, RequestHash: hash}})
	if callErr != nil {
		return nil, errors.Join(ErrIssuerUnavailable, ctx.Err())
	}
	if result.Token == "" || len(result.Token) > MaxTokenBytes || strings.ContainsAny(result.Token, " \t\r\n") || !time.Now().Before(result.ExpiresAt) || result.ExpiresAt.After(p.expires) || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	out.Header.Set(HeaderAuthorization, "Bearer "+result.Token)
	handedOff = true
	resp, err = t.base.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		cancel()
	} else {
		resp.Body = &deadlineBody{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

type deadlineBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.cancel()
	}
	return n, err
}
func (b *deadlineBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }
