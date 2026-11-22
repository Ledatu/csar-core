package origincontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const MaxBodyBytes = 1 << 20

type replayBody struct {
	io.Reader
	io.Closer
}

// RequestHash covers the original router URI, method, body and interpretation
// headers. It restores the body, including its closer, for downstream consumers.
// RequestURI takes precedence because route rewriting must not change the proof.
func RequestHash(r *http.Request) (string, error) {
	if r == nil || r.URL == nil {
		return "", ErrInvalid
	}
	interpretation := make([]string, 0, 2)
	for _, target := range []string{"Content-Type", "Content-Encoding"} {
		count := 0
		value := ""
		for name, values := range r.Header {
			if strings.EqualFold(name, target) {
				count += len(values)
				if len(values) == 1 {
					value = values[0]
				}
			}
		}
		if count > 1 {
			return "", ErrInvalid
		}
		interpretation = append(interpretation, value)
	}
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	if len(uri) > 8192 || len(interpretation[0]) > 512 || len(interpretation[1]) > 128 {
		return "", ErrInvalid
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return "", ErrInvalid
	}
	var body []byte
	if r.Body != nil {
		original := r.Body
		var err error
		body, err = io.ReadAll(io.LimitReader(original, MaxBodyBytes+1))
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(body), original), Closer: original}
		if err != nil || len(body) > MaxBodyBytes {
			return "", ErrInvalid
		}
	}
	digest := sha256.Sum256(body)
	fields := []string{r.Method, uri, interpretation[0], interpretation[1], hex.EncodeToString(digest[:])}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return "", ErrInvalid
	}
	result := sha256.Sum256(encoded)
	return hex.EncodeToString(result[:]), nil
}
