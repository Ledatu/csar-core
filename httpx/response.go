package httpx

import (
	"encoding/json"
	"io"
	"net/http"

	stderrors "errors"

	csarerrors "github.com/ledatu/csar-core/errors"
)

const maxReadJSONBytes = 1 << 20 // 1 MiB

// WriteJSON serializes v as JSON and writes it with the given HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a structured JSON error response. If err is a
// *csarerrors.Error, its Code and Status are used. Otherwise a generic 500
// response is returned (the original error is never leaked to the client).
func WriteError(w http.ResponseWriter, err error) {
	var domainErr *csarerrors.Error
	if stderrors.As(err, &domainErr) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(domainErr.Status)
		_ = json.NewEncoder(w).Encode(errorBody{
			Error: errorDetail{
				Code:    string(domainErr.Code),
				Message: domainErr.Message,
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(errorBody{
		Error: errorDetail{
			Code:    string(csarerrors.CodeInternal),
			Message: "internal error",
		},
	})
}

// ReadJSON decodes a JSON request body into v. The body is limited to 1 MiB.
// Returns a domain Validation error on malformed input.
func ReadJSON(r *http.Request, v any) error {
	body := http.MaxBytesReader(nil, r.Body, maxReadJSONBytes)
	defer body.Close()

	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return csarerrors.Validation("invalid JSON: %v", err)
	}

	if dec.More() {
		return csarerrors.Validation("request body must contain a single JSON object")
	}
	return nil
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Drain reads and discards the remaining request body so the underlying
// connection can be reused. Call it in deferred cleanup when needed.
func Drain(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
}
