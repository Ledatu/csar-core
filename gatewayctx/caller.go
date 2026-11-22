package gatewayctx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/caller"
)

const (
	HeaderCaller = "X-Gateway-Caller"
	// Reserved for verified origin propagation; parsing it is not supported yet.
	HeaderOriginCaller   = "X-Gateway-Origin-Caller"
	MaxCallerHeaderBytes = 4096
)

var ErrInvalidCaller = errors.New("gatewayctx: invalid caller metadata")

// SetCaller replaces optional metadata after credential verification. It binds
// to the subject/credential headers already asserted by the gateway. Nil clears
// metadata for legacy issuers. It never conveys a permission or origin proof.
func SetCaller(h http.Header, id *caller.Identity) error {
	for name := range h {
		if strings.EqualFold(name, HeaderCaller) {
			delete(h, name)
		}
	}
	if id == nil {
		return nil
	}
	if validateCallerEnvelope(h, id) != nil {
		return ErrInvalidCaller
	}
	body, err := json.Marshal(id)
	if err != nil {
		return ErrInvalidCaller
	}
	value := base64.RawURLEncoding.EncodeToString(body)
	if len(value) > MaxCallerHeaderBytes {
		return ErrInvalidCaller
	}
	h.Set(HeaderCaller, value)
	return nil
}

// CallerFromHeaders checks shape and envelope consistency, not source trust.
// Absence is legacy-compatible; malformed present metadata is an error.
func CallerFromHeaders(h http.Header) (*caller.Identity, error) {
	value, present, err := singleCallerHeader(h, HeaderCaller)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	if value == "" || len(value) > MaxCallerHeaderBytes {
		return nil, ErrInvalidCaller
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, ErrInvalidCaller
	}
	var id caller.Identity
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&id) != nil || decoder.Decode(new(any)) != io.EOF ||
		validateCallerEnvelope(h, &id) != nil {
		return nil, ErrInvalidCaller
	}
	return &id, nil
}

func validateCallerEnvelope(h http.Header, id *caller.Identity) error {
	subject, _, err := singleCallerHeader(h, HeaderSubject)
	if err != nil {
		return err
	}
	credential, _, err := singleCallerHeader(h, HeaderCredentialID)
	if err != nil {
		return err
	}
	return id.ValidateBinding(subject, credential)
}

func singleCallerHeader(h http.Header, target string) (value string, present bool, err error) {
	for name, values := range h {
		if !strings.EqualFold(name, target) {
			continue
		}
		if present || len(values) != 1 {
			return "", false, ErrInvalidCaller
		}
		present, value = true, values[0]
	}
	return value, present, nil
}
