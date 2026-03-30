package health

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandler_ReturnsOK(t *testing.T) {
	h := Handler("1.0.0")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.Status != "ok" {
		t.Errorf("Status = %q, want %q", s.Status, "ok")
	}
	if s.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", s.Version, "1.0.0")
	}
}

func TestHandler_DifferentVersions(t *testing.T) {
	for _, v := range []string{"dev", "2.0.0-rc1", "0.0.1"} {
		t.Run(v, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler(v)(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			var s Status
			_ = json.NewDecoder(rec.Result().Body).Decode(&s)
			if s.Version != v {
				t.Errorf("Version = %q, want %q", s.Version, v)
			}
		})
	}
}

func TestReadinessChecker_AllOK(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "ok"} })
	rc.Register("cache", func() CheckStatus { return CheckStatus{Status: "ok"} })

	rs := rc.Check()
	if rs.Status != "ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "ready")
	}
	if len(rs.Checks) != 2 {
		t.Errorf("Checks length = %d, want 2", len(rs.Checks))
	}
}

func TestReadinessChecker_Degraded(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "ok"} })
	rc.Register("cache", func() CheckStatus { return CheckStatus{Status: "degraded", Detail: "high latency"} })

	rs := rc.Check()
	if rs.Status != "degraded" {
		t.Errorf("Status = %q, want %q", rs.Status, "degraded")
	}
}

func TestReadinessChecker_NotReady(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "fail", Detail: "connection refused"} })
	rc.Register("cache", func() CheckStatus { return CheckStatus{Status: "ok"} })

	rs := rc.Check()
	if rs.Status != "not_ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "not_ready")
	}
}

func TestReadinessChecker_FailOverridesDegraded(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "fail"} })
	rc.Register("cache", func() CheckStatus { return CheckStatus{Status: "degraded"} })

	rs := rc.Check()
	if rs.Status != "not_ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "not_ready")
	}
}

func TestReadinessChecker_NoDetails(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", false)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "ok"} })

	rs := rc.Check()
	if rs.Checks != nil {
		t.Errorf("expected nil Checks when details disabled, got %v", rs.Checks)
	}
}

func TestReadinessChecker_NoChecks(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rs := rc.Check()
	if rs.Status != "ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "ready")
	}
}

func TestReadinessChecker_Handler_OK(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "ok"} })

	rec := httptest.NewRecorder()
	rc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readiness", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadinessChecker_Handler_503(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true)
	rc.Register("db", func() CheckStatus { return CheckStatus{Status: "fail"} })

	rec := httptest.NewRecorder()
	rc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readiness", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestReadinessChecker_PanickingCheck(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true, WithCheckTimeout(2*time.Second))
	rc.Register("good", func() CheckStatus { return CheckStatus{Status: "ok"} })
	rc.Register("bad", func() CheckStatus { panic("check exploded") })

	rs := rc.Check()
	if rs.Status != "not_ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "not_ready")
	}
	bad, ok := rs.Checks["bad"]
	if !ok {
		t.Fatal("missing 'bad' check result")
	}
	if bad.Status != "fail" {
		t.Errorf("bad.Status = %q, want %q", bad.Status, "fail")
	}
	if !strings.Contains(bad.Detail, "panic") {
		t.Errorf("bad.Detail = %q, expected panic detail", bad.Detail)
	}
	good, ok := rs.Checks["good"]
	if !ok {
		t.Fatal("missing 'good' check result")
	}
	if good.Status != "ok" {
		t.Errorf("good.Status = %q, want %q", good.Status, "ok")
	}
}

func TestReadinessChecker_HungCheck(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true, WithCheckTimeout(100*time.Millisecond))
	rc.Register("fast", func() CheckStatus { return CheckStatus{Status: "ok"} })
	rc.Register("hung", func() CheckStatus {
		time.Sleep(10 * time.Second)
		return CheckStatus{Status: "ok"}
	})

	start := time.Now()
	rs := rc.Check()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("Check took %v; should have timed out in ~100ms", elapsed)
	}
	if rs.Status != "not_ready" {
		t.Errorf("Status = %q, want %q", rs.Status, "not_ready")
	}
	hung := rs.Checks["hung"]
	if hung.Status != "fail" {
		t.Errorf("hung.Status = %q, want %q", hung.Status, "fail")
	}
	if !strings.Contains(hung.Detail, "timed out") {
		t.Errorf("hung.Detail = %q, expected timeout detail", hung.Detail)
	}
}

func TestReadinessChecker_CustomTimeout(t *testing.T) {
	rc := NewReadinessChecker("1.0.0", true, WithCheckTimeout(50*time.Millisecond))
	if rc.checkTimeout != 50*time.Millisecond {
		t.Errorf("checkTimeout = %v, want 50ms", rc.checkTimeout)
	}
}

func TestTCPDialCheck_OK(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	check := TCPDialCheck(ln.Addr().String(), 250*time.Millisecond)
	got := check()
	if got.Status != "ok" {
		t.Fatalf("status = %q, want ok (%s)", got.Status, got.Detail)
	}
}

func TestTCPDialCheck_WildcardAddrUsesLoopback(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	check := TCPDialCheck(":"+port, 250*time.Millisecond)
	got := check()
	if got.Status != "ok" {
		t.Fatalf("status = %q, want ok (%s)", got.Status, got.Detail)
	}
}

func TestTCPDialCheck_Fail(t *testing.T) {
	t.Parallel()

	check := TCPDialCheck("127.0.0.1:1", 50*time.Millisecond)
	got := check()
	if got.Status != "fail" {
		t.Fatalf("status = %q, want fail", got.Status)
	}
	if got.Detail == "" {
		t.Fatal("expected failure detail")
	}
}
