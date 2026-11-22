package origincontext

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/csarclient"
	"github.com/ledatu/csar-core/jwtx"
)

var ErrIssuerUnavailable = errors.New("origincontext: issuer unavailable")

type RootClientConfig struct {
	Endpoint   string
	Issuer     string
	HTTPClient *http.Client
	// KeyFunc resolves already trusted issuer keys; callers must bound any IO.
	KeyFunc jwtx.KeyFunc
	// KeyFuncContext is preferred for resolvers that may perform network IO.
	KeyFuncContext func(context.Context) jwtx.KeyFunc
}

// Proof contains a credential, not an audit/response DTO. Do not persist it.
type Proof struct {
	Token  string
	Claims *Claims
}

// RootClient is for the trusted gateway's dedicated mTLS issuer ingress.
// Backend services delegate through CSAR/STS; they cannot assert root callers.
type RootClient struct {
	client       *csarclient.Client
	transport    *http.Transport
	path, issuer string
	keys         jwtx.KeyFunc
	keysContext  func(context.Context) jwtx.KeyFunc
}

func NewRootClient(cfg RootClientConfig) (*RootClient, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path == "" || cfg.Issuer == "" || (cfg.KeyFunc == nil) == (cfg.KeyFuncContext == nil) || cfg.HTTPClient == nil || cfg.HTTPClient.Jar != nil {
		return nil, ErrInvalid
	}
	if u.RawPath != "" || path.Clean(u.Path) != u.Path || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return nil, ErrInvalid
	}
	transport, ok := cfg.HTTPClient.Transport.(*http.Transport)
	if !ok || transport == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || len(transport.TLSClientConfig.Certificates) == 0 && transport.TLSClientConfig.GetClientCertificate == nil {
		return nil, ErrInvalid
	}
	if version := transport.TLSClientConfig.MinVersion; version != 0 && version < tls.VersionTLS12 {
		return nil, ErrInvalid
	}
	transport = transport.Clone()
	client := *cfg.HTTPClient
	client.Transport = transport
	base := *u
	base.Path = ""
	base.RawPath = ""
	shared, err := csarclient.New(csarclient.Config{BaseURL: base.String(), HTTPClient: &client, Timeout: 5 * time.Second, MaxRequestBytes: 16 << 10, MaxResponseBytes: 16 << 10})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, ErrInvalid
	}
	return &RootClient{client: shared, transport: transport, path: u.EscapedPath(), issuer: cfg.Issuer, keys: cfg.KeyFunc, keysContext: cfg.KeyFuncContext}, nil
}

func (c *RootClient) Close() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// Issue requires an already verified principal and a source validation deadline.
// It creates no cache entry and never retries a root issuance automatically.
func (c *RootClient) Issue(ctx context.Context, in *RootRequest) (*Proof, error) {
	if c == nil || in == nil || in.Caller.Validate() != nil || in.Receiver == "" || !caller.ValidReference(in.Receiver) || in.Resource == "" || !caller.ValidReference(in.Resource) || !validHash(in.RequestHash) || !time.Now().Before(in.SourceExpiresAt) {
		return nil, ErrInvalid
	}
	request := *in
	principal := *in.Caller
	request.Caller = &principal
	ctx, budgetCancel := context.WithTimeout(ctx, 5*time.Second)
	defer budgetCancel()
	ctx, cancel := context.WithDeadline(ctx, request.SourceExpiresAt)
	defer cancel()
	response, callErr := csarclient.DoJSON[Response](ctx, c.client, csarclient.Request{Method: http.MethodPost, Path: c.path, Body: &request})
	if callErr != nil {
		return nil, errors.Join(ErrIssuerUnavailable, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrIssuerUnavailable, err)
	}
	keys := c.keys
	if c.keysContext != nil {
		keys = c.keysContext(ctx)
	}
	claims, err := Verify(response.Token, keys, c.issuer, request.Receiver)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(ErrIssuerUnavailable, contextErr)
	}
	if err != nil || claims.Depth != 0 || *claims.Origin != principal || claims.Resource != request.Resource || claims.RequestHash != request.RequestHash || !claims.ExpiresAt.Equal(response.ExpiresAt) || response.ExpiresAt.After(request.SourceExpiresAt) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrIssuerUnavailable, err)
	}
	return &Proof{Token: response.Token, Claims: claims}, nil
}
