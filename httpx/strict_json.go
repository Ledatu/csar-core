package httpx

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	csarerrors "github.com/ledatu/csar-core/errors"
)

// ReadStrictJSON is opt-in decoding for security request objects. In addition to
// ReadJSON it rejects duplicate/case-aliased keys, invalid UTF-8 and nesting over
// 64 levels. Case aliases are ambiguous to encoding/json's struct field matcher.
// Existing callers of ReadJSON retain their compatibility behavior.
func ReadStrictJSON(r *http.Request, out any) error {
	invalid := csarerrors.Validation("invalid or ambiguous JSON object")
	if r == nil || r.Body == nil {
		return invalid
	}
	body := http.MaxBytesReader(nil, r.Body, maxReadJSONBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil || !utf8.Valid(data) {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') || !strictJSONContainer(decoder, '{', 1) {
		return invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid
	}
	// Reuse the canonical unknown-field and complete-document decoder, keeping
	// expanded/raw request values out of public security validation errors.
	copyRequest := r.Clone(r.Context())
	copyRequest.Body = io.NopCloser(bytes.NewReader(data))
	if ReadJSON(copyRequest, out) != nil {
		return invalid
	}
	return nil
}

func strictJSONContainer(decoder *json.Decoder, opening json.Delim, depth int) bool {
	if depth > 64 {
		return false
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if opening == '{' {
			token, err := decoder.Token()
			key, ok := token.(string)
			// EqualFold semantics match encoding/json, including Unicode aliases.
			folded := foldJSONKey(key)
			if err != nil || !ok || keys[folded] {
				return false
			}
			keys[folded] = true
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if delimiter, container := token.(json.Delim); container {
			if delimiter != '{' && delimiter != '[' || !strictJSONContainer(decoder, delimiter, depth+1) {
				return false
			}
		}
	}
	closing := json.Delim('}')
	if opening == '[' {
		closing = ']'
	}
	last, err := decoder.Token()
	return err == nil && last == closing
}

func foldJSONKey(key string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < minimum {
				minimum = folded
			}
		}
		return minimum
	}, key)
}
