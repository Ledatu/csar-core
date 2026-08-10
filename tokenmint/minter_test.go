package tokenmint_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/tokenmint"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testConfig builds a single-profile config pointed at srv. AllowPrivate is on
// because httptest binds loopback, which the dial guard blocks by default.
func testConfig(t *testing.T, tokenURL string, mutate func(*tokenmint.Profile)) *tokenmint.Config {
	t.Helper()

	u, err := url.Parse(tokenURL)
	if err != nil {
		t.Fatalf("parse token url: %v", err)
	}

	p := tokenmint.Profile{
		TokenURL:               tokenURL,
		BodyStyle:              tokenmint.BodyStyleJSON,
		StaticParams:           map[string]string{"grant_type": "client_credentials"},
		ClientIDParam:          "client_id",
		ClientSecretParam:      "client_secret",
		AccessTokenPath:        "access_token",
		ExpiresInPath:          "expires_in",
		TokenTypePath:          "token_type",
		ExpectedTokenType:      "Bearer",
		DefaultExpiresIn:       30 * time.Minute,
		ExpiresInHaircut:       0.9,
		RefreshMargin:          5 * time.Minute,
		MinRefreshInterval:     0,
		ErrorBackoffBase:       30 * time.Second,
		ErrorBackoffMax:        5 * time.Minute,
		AuthErrorBackoff:       15 * time.Minute,
		IdleTTL:                90 * time.Minute,
		Timeout:                5 * time.Second,
		MaxResponseBytes:       64 << 10,
		MaxMintsPerMinute:      600,
		SecretRefScopeSegments: 3,
	}
	if mutate != nil {
		mutate(&p)
	}

	cfg := &tokenmint.Config{
		AllowedHosts: []string{u.Hostname()},
		AllowPrivate: true,
		Profiles:     map[string]tokenmint.Profile{"test": p},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return cfg
}

func newMinter(t *testing.T, cfg *tokenmint.Config) *tokenmint.Minter {
	t.Helper()
	m, err := tokenmint.New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	return m
}

func TestMintHappyPath(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"client_secret":"s3cret"`) {
			t.Errorf("credential not present in request body: %s", body)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok-1","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	m := newMinter(t, testConfig(t, srv.URL, nil))
	start := time.Now()

	res, err := m.Mint(context.Background(), "test", "cid", "s3cret")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.AccessToken != "tok-1" {
		t.Errorf("AccessToken = %q, want tok-1", res.AccessToken)
	}
	if res.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", res.TokenType)
	}

	// 1800s * 0.9 haircut = 27m hard expiry; refresh 5m earlier at 22m.
	if d := res.HardExpiry.Sub(start); d < 26*time.Minute || d > 28*time.Minute {
		t.Errorf("HardExpiry is %v out, want ~27m", d)
	}
	if d := res.RefreshAfter.Sub(start); d < 21*time.Minute || d > 23*time.Minute {
		t.Errorf("RefreshAfter is %v out, want ~22m", d)
	}

	// A second call inside the freshness window must not touch the network.
	if _, err := m.Mint(context.Background(), "test", "cid", "s3cret"); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestMintDefaultsExpiryWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer"}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) {
		p.DefaultExpiresIn = 10 * time.Minute
		p.RefreshMargin = time.Minute
	})
	start := time.Now()

	res, err := newMinter(t, cfg).Mint(context.Background(), "test", "cid", "sec")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if d := res.HardExpiry.Sub(start); d < 8*time.Minute || d > 10*time.Minute {
		t.Errorf("HardExpiry is %v out, want ~9m (10m default with 0.9 haircut)", d)
	}
}

func TestMintRejectsTokenTypeMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok","expires_in":1800,"token_type":"MAC"}`)
	}))
	defer srv.Close()

	_, err := newMinter(t, testConfig(t, srv.URL, nil)).Mint(context.Background(), "test", "cid", "sec")
	if !errors.Is(err, tokenmint.ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

func TestMintRejectsOversizeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"access_token":"%s","expires_in":1800,"token_type":"Bearer"}`, strings.Repeat("A", 4096))
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) { p.MaxResponseBytes = 512 })
	_, err := newMinter(t, cfg).Mint(context.Background(), "test", "cid", "sec")
	if !errors.Is(err, tokenmint.ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

func TestMintClassifiesInvalidClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"client_secret=hunter2 rejected"}`)
	}))
	defer srv.Close()

	_, err := newMinter(t, testConfig(t, srv.URL, nil)).Mint(context.Background(), "test", "cid", "hunter2")
	if !errors.Is(err, tokenmint.ErrInvalidClient) {
		t.Fatalf("err = %v, want ErrInvalidClient", err)
	}
	// The upstream echoed the secret in its description; it must not survive
	// into an error string that will be logged.
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks the client secret: %v", err)
	}
}

func TestMintBacksOffWithoutFurtherCalls(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := newMinter(t, testConfig(t, srv.URL, nil))

	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); !errors.Is(err, tokenmint.ErrUpstream) {
		t.Fatalf("first mint err = %v, want ErrUpstream", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := m.Mint(context.Background(), "test", "cid", "sec"); !errors.Is(err, tokenmint.ErrBackoff) {
			t.Fatalf("mint %d err = %v, want ErrBackoff", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d during backoff, want 1", got)
	}
}

func TestMintHonorsRetryAfterOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := newMinter(t, testConfig(t, srv.URL, nil))
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); !errors.Is(err, tokenmint.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
	_, err := m.Mint(context.Background(), "test", "cid", "sec")
	if !errors.Is(err, tokenmint.ErrBackoff) {
		t.Fatalf("err = %v, want ErrBackoff", err)
	}
}

func TestMintServesCachedTokenWhileUpstreamIsDown(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `{"access_token":"tok-1","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, nil)
	m := newMinter(t, cfg)

	base := time.Now()
	m.SetClock(func() time.Time { return base })
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); err != nil {
		t.Fatalf("initial mint: %v", err)
	}

	// Move past the refresh point but well before hard expiry, and break the
	// upstream. The existing token must keep being served.
	fail.Store(true)
	m.SetClock(func() time.Time { return base.Add(24 * time.Minute) })

	res, err := m.Mint(context.Background(), "test", "cid", "sec")
	if err != nil {
		t.Fatalf("mint during outage: %v", err)
	}
	if res.AccessToken != "tok-1" {
		t.Errorf("AccessToken = %q, want the cached tok-1", res.AccessToken)
	}

	// Past hard expiry there is nothing safe left to serve, so it must fail.
	m.SetClock(func() time.Time { return base.Add(40 * time.Minute) })
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); err == nil {
		t.Fatal("expected an error once the cached token passed hard expiry")
	}
}

func TestMintCollapsesConcurrentCalls(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		fmt.Fprint(w, `{"access_token":"tok","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	m := newMinter(t, testConfig(t, srv.URL, nil))

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Mint(context.Background(), "test", "cid", "sec"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent mint: %v", err)
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d for 100 concurrent mints, want 1", got)
	}
}

func TestMintSharesOneCallAcrossProfilesWithSameCredential(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"access_token":"tok","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	m := newMinter(t, testConfig(t, srv.URL, nil))
	for i := 0; i < 3; i++ {
		if _, err := m.Mint(context.Background(), "test", "same-client", "sec"); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

// TestMintRefusesRedirect is the credential-leak regression. A token endpoint
// that answers 302 must not cause the client_secret to be replayed to the
// redirect target.
func TestMintRefusesRedirect(t *testing.T) {
	var attackerHits atomic.Int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHits.Add(1)
		fmt.Fprint(w, `{"access_token":"attacker","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer origin.Close()

	_, err := newMinter(t, testConfig(t, origin.URL, nil)).Mint(context.Background(), "test", "cid", "sec")
	if err == nil {
		t.Fatal("expected the redirect to fail the mint")
	}
	if got := attackerHits.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0 — the credential was replayed", got)
	}
}

func TestMintRejectsUnknownProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be contacted for an unknown profile")
	}))
	defer srv.Close()

	_, err := newMinter(t, testConfig(t, srv.URL, nil)).Mint(context.Background(), "nope", "cid", "sec")
	if !errors.Is(err, tokenmint.ErrUnknownProfile) {
		t.Fatalf("err = %v, want ErrUnknownProfile", err)
	}
}

func TestMintRespectsMinRefreshInterval(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		// Very short lifetime, so every call is immediately due for refresh.
		fmt.Fprint(w, `{"access_token":"tok","expires_in":2,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) {
		p.MinRefreshInterval = time.Hour
		p.RefreshMargin = time.Second
		p.DefaultExpiresIn = time.Minute
	})
	m := newMinter(t, cfg)

	base := time.Now()
	m.SetClock(func() time.Time { return base })
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); err != nil {
		t.Fatalf("initial mint: %v", err)
	}

	// Past hard expiry, so no cached fallback is available, but still inside
	// the minimum refresh interval.
	m.SetClock(func() time.Time { return base.Add(10 * time.Second) })
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); !errors.Is(err, tokenmint.ErrThrottled) {
		t.Fatalf("err = %v, want ErrThrottled", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestSweepDropsIdleState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) { p.IdleTTL = 30 * time.Minute })
	m := newMinter(t, cfg)

	base := time.Now()
	m.SetClock(func() time.Time { return base })
	if _, err := m.Mint(context.Background(), "test", "cid", "sec"); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if m.Entries() != 1 {
		t.Fatalf("Entries = %d, want 1", m.Entries())
	}

	// Inside the idle window with a still-usable token: keep it.
	m.SetClock(func() time.Time { return base.Add(20 * time.Minute) })
	if dropped := m.Sweep(); dropped != 0 {
		t.Errorf("Sweep dropped %d entries early, want 0", dropped)
	}

	// Past both the idle TTL and hard expiry: drop it.
	m.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	if dropped := m.Sweep(); dropped != 1 {
		t.Errorf("Sweep dropped %d entries, want 1", dropped)
	}
	if m.Entries() != 0 {
		t.Errorf("Entries = %d after sweep, want 0", m.Entries())
	}
}

func TestMintFormBodyStyle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.PostForm.Get("client_id"); got != "cid" {
			t.Errorf("client_id = %q, want cid", got)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", got)
		}
		fmt.Fprint(w, `{"access_token":"tok","expires_in":1800,"token_type":"Bearer"}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) { p.BodyStyle = tokenmint.BodyStyleForm })
	if _, err := newMinter(t, cfg).Mint(context.Background(), "test", "cid", "sec"); err != nil {
		t.Fatalf("mint: %v", err)
	}
}

func TestMintNestedResponsePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":{"token":"nested-tok","ttl":600}}`)
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL, func(p *tokenmint.Profile) {
		p.AccessTokenPath = "data.token"
		p.ExpiresInPath = "data.ttl"
		p.TokenTypePath = "data.type"
		p.ExpectedTokenType = ""
		p.RefreshMargin = time.Minute
	})

	res, err := newMinter(t, cfg).Mint(context.Background(), "test", "cid", "sec")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.AccessToken != "nested-tok" {
		t.Errorf("AccessToken = %q, want nested-tok", res.AccessToken)
	}
}
