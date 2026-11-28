package clientx_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/httpx/clientx"
	"github.com/ledatu/csar-core/httpx/jsonstream"
)

type streamPage struct {
	Rows []payload `json:"rows"`
}

func streamFields(out *streamPage) []jsonstream.Field {
	return []jsonstream.Field{jsonstream.Array("rows", &out.Rows)}
}

type streamTransport func(*http.Request) (*http.Response, error)

func (f streamTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type streamBody struct {
	io.Reader
	closed  bool
	failure error
}

func (b *streamBody) Close() error { b.closed = true; return nil }
func (b *streamBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if remaining, ok := b.Reader.(interface{ Len() int }); ok && remaining.Len() == 0 && b.failure != nil {
		err = b.failure
		b.failure = nil
	}
	return n, err
}

func TestStreamingHTTPContractMatchesBuffered(t *testing.T) {
	broken := errors.New("body fixture read failed")
	for _, tc := range []struct {
		name, body string
		status     int
		limit      int64
		readErr    error
	}{
		{"success", `{"rows":[{"name":"a","n":1}]}`, 200, 1000, nil},
		{"accepted status", `{"rows":[]}`, 202, 1000, nil},
		{"duplicate", `{"rows":[{"name":"kept"}],"rows":[{"n":2}]}`, 200, 1000, nil},
		{"late syntax", `{"rows":[{"name":"valid"}],"tail":{`, 200, 1000, nil},
		{"typed failure", `{"rows":[{"n":"wrong"}]}`, 200, 1000, nil},
		{"trailing value", `{"rows":[]} true`, 200, 1000, nil},
		{"oversize", `{"rows":[]}` + strings.Repeat(" ", 5000), 200, 32, nil},
		{"read failure", `{"rows":[]}`, 200, 1000, broken},
		{"read before size", `{"rows":[]}`, 200, 9, broken},
		{"status v1", `{"code":"throttled","status":503,"retry_after_ms":6000}`, 503, 1000, nil},
		{"non JSON status", `not JSON`, 403, 1000, nil},
		{"status oversize", strings.Repeat("x", 5000), 503, 32, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var oldValue streamPage
			var oldError *clientx.Error
			for _, streaming := range []bool{false, true} {
				body := &streamBody{Reader: strings.NewReader(tc.body), failure: tc.readErr}
				calls := 0
				client := &http.Client{Transport: streamTransport(func(*http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: tc.status, Body: body, Header: http.Header{"Retry-After": {"2"}, "X-Csar-Status": {"throttled"}, "X-Csar-Wait-Ms": {"3000"}, "X-Csar-Protocol-Version": {"1"}}}, nil
				})}
				req := newRequest(t, t.Context(), http.MethodPost, "https://router.invalid/svc/future/data")
				opts := clientx.Options{Client: client, MaxResponseBytes: tc.limit, Timeout: time.Second}
				var value streamPage
				var cerr *clientx.Error
				if streaming {
					value, cerr = clientx.DoJSONStream(t.Context(), req, opts, streamFields)
				} else {
					value, cerr = clientx.DoJSON[streamPage](t.Context(), req, opts)
				}
				if !body.closed || calls != 1 {
					t.Fatal("cleanup or request attempt count changed")
				}
				if !streaming {
					oldValue, oldError = value, cerr
					continue
				}
				if !reflect.DeepEqual(value, oldValue) || (cerr == nil) != (oldError == nil) {
					t.Fatalf("result changed: old=%+v/%v new=%+v/%v", oldValue, oldError, value, cerr)
				}
				if cerr == nil {
					continue
				}
				if cerr.Status != oldError.Status || cerr.Path != oldError.Path || cerr.Method != oldError.Method || cerr.Origin != oldError.Origin || cerr.RetryAfter != oldError.RetryAfter || cerr.CSARStatus != oldError.CSARStatus || cerr.CSARWait != oldError.CSARWait || cerr.RetryAfterHeader != oldError.RetryAfterHeader || !reflect.DeepEqual(cerr.Body, oldError.Body) {
					t.Fatalf("error envelope changed: old=%+v new=%+v", oldError, cerr)
				}
				if errors.Is(cerr, clientx.ErrResponseTooLarge) != errors.Is(oldError, clientx.ErrResponseTooLarge) || errors.Is(cerr, broken) != errors.Is(oldError, broken) {
					t.Fatal("error identity changed")
				}
				var oldSyntax, newSyntax *json.SyntaxError
				var oldType, newType *json.UnmarshalTypeError
				if errors.As(cerr, &newSyntax) != errors.As(oldError, &oldSyntax) || errors.As(cerr, &newType) != errors.As(oldError, &oldType) {
					t.Fatal("JSON error class changed")
				}
			}
		})
	}
}
