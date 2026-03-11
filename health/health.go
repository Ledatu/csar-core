// Package health provides standard liveness and readiness probe handlers
// for CSAR microservices. All services sharing this package expose a
// consistent probe contract for orchestrators and load balancers.
package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const defaultCheckTimeout = 5 * time.Second

// Status is the JSON body returned by the liveness probe.
type Status struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Handler returns an HTTP handler for liveness probes.
// It always responds 200 with {"status":"ok","version":"..."}.
func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Status{
			Status:  "ok",
			Version: version,
		})
	}
}

// CheckStatus represents the health of a single dependency.
type CheckStatus struct {
	Status string `json:"status"` // "ok", "degraded", "fail"
	Detail string `json:"detail,omitempty"`
}

// ReadinessStatus represents the aggregate readiness with per-dependency checks.
type ReadinessStatus struct {
	Status  string                 `json:"status"` // "ready", "degraded", "not_ready"
	Version string                 `json:"version"`
	Checks  map[string]CheckStatus `json:"checks,omitempty"`
}

// CheckFunc probes a single dependency and returns its status.
type CheckFunc func() CheckStatus

// ReadinessChecker aggregates multiple named dependency checks
// and produces an aggregate readiness response.
type ReadinessChecker struct {
	mu           sync.RWMutex
	checks       map[string]CheckFunc
	version      string
	details      bool
	checkTimeout time.Duration
}

// Option configures a ReadinessChecker.
type Option func(*ReadinessChecker)

// WithCheckTimeout sets the maximum duration each individual health
// check is allowed to run before being treated as a failure. Default: 5s.
func WithCheckTimeout(d time.Duration) Option {
	return func(rc *ReadinessChecker) { rc.checkTimeout = d }
}

// NewReadinessChecker creates a new checker. When includeDetails is false,
// individual check results are omitted from the response body.
func NewReadinessChecker(version string, includeDetails bool, opts ...Option) *ReadinessChecker {
	rc := &ReadinessChecker{
		checks:       make(map[string]CheckFunc),
		version:      version,
		details:      includeDetails,
		checkTimeout: defaultCheckTimeout,
	}
	for _, o := range opts {
		o(rc)
	}
	return rc
}

// Register adds a named dependency check. Safe for concurrent use.
func (rc *ReadinessChecker) Register(name string, check CheckFunc) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.checks[name] = check
}

// Check runs all registered checks concurrently with per-check timeout
// and panic recovery. A check that exceeds the timeout is reported as
// "fail" with a timeout detail. A check that panics is reported as
// "fail" with the panic value.
func (rc *ReadinessChecker) Check() ReadinessStatus {
	rc.mu.RLock()
	checks := make(map[string]CheckFunc, len(rc.checks))
	for k, v := range rc.checks {
		checks[k] = v
	}
	rc.mu.RUnlock()

	ch := make(chan checkResult, len(checks))
	timeout := rc.checkTimeout

	for name, fn := range checks {
		go func(n string, f CheckFunc) {
			ch <- runCheck(n, f, timeout)
		}(name, fn)
	}

	rs := ReadinessStatus{
		Status:  "ready",
		Version: rc.version,
		Checks:  make(map[string]CheckStatus, len(checks)),
	}

	hasFail := false
	hasDegraded := false

	for range checks {
		r := <-ch
		rs.Checks[r.name] = r.status
		switch r.status.Status {
		case "fail":
			hasFail = true
		case "degraded":
			hasDegraded = true
		}
	}

	if hasFail {
		rs.Status = "not_ready"
	} else if hasDegraded {
		rs.Status = "degraded"
	}

	if !rc.details {
		rs.Checks = nil
	}

	return rs
}

// Handler returns an HTTP handler for readiness probes.
// It returns 503 when the aggregate status is "not_ready".
func (rc *ReadinessChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := rc.Check()
		w.Header().Set("Content-Type", "application/json")
		if status.Status == "not_ready" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(status)
	}
}

type checkResult struct {
	name   string
	status CheckStatus
}

func runCheck(name string, fn CheckFunc, timeout time.Duration) checkResult {
	done := make(chan CheckStatus, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				done <- CheckStatus{
					Status: "fail",
					Detail: fmt.Sprintf("panic: %v", v),
				}
			}
		}()
		done <- fn()
	}()

	select {
	case cs := <-done:
		return checkResult{name: name, status: cs}
	case <-time.After(timeout):
		return checkResult{name: name, status: CheckStatus{
			Status: "fail",
			Detail: fmt.Sprintf("check timed out after %s", timeout),
		}}
	}
}
