package gatewayctx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
)

const (
	HeaderOriginAccount     = "X-Gateway-Origin-Account"
	HeaderOperationID       = "X-Gateway-Operation-ID"
	HeaderParentOperationID = "X-Gateway-Parent-Operation-ID"
	HeaderOriginExpiresAt   = "X-Gateway-Origin-Expires-At"
)

// Origin is gateway-asserted attribution, not additional access authority.
// It intentionally contains no raw proof/token; services still require trusted
// gateway ingress, and delegate opaque proofs through the issuer via CSAR/STS.
type Origin struct {
	Account                        *authntokens.AccountBinding
	Caller                         *caller.Identity
	OperationID, ParentOperationID string
	ExpiresAt                      time.Time
}

func validOrigin(o *Origin) bool {
	if o == nil || o.Caller.Validate() != nil || o.ExpiresAt.IsZero() || !originOperation(o.OperationID) {
		return false
	}
	if o.Account != nil && o.Account.Validate(o.Caller) != nil {
		return false
	}
	return o.ParentOperationID == "" || o.ParentOperationID != o.OperationID && originOperation(o.ParentOperationID)
}
func originOperation(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// SetOrigin is called by the gateway after signature and resource checks. It
// preserves the separately authenticated immediate Caller and Subject headers.
func SetOrigin(h http.Header, o *Origin) error {
	for name := range h {
		for _, target := range []string{HeaderOriginCaller, HeaderOperationID, HeaderParentOperationID, HeaderOriginExpiresAt, HeaderOriginAccount} {
			if strings.EqualFold(name, target) {
				delete(h, name)
			}
		}
	}
	if o == nil {
		return nil
	}
	if !validOrigin(o) {
		return ErrInvalidCaller
	}
	value, err := encodeCaller(o.Caller)
	if err != nil {
		return err
	}
	if o.Account != nil {
		body, _ := json.Marshal(o.Account)
		binding := base64.RawURLEncoding.EncodeToString(body)
		if len(binding) > MaxCallerHeaderBytes {
			return ErrInvalidCaller
		}
		h.Set(HeaderOriginAccount, binding)
	}
	h.Set(HeaderOriginCaller, value)
	h.Set(HeaderOperationID, o.OperationID)
	h.Set(HeaderOriginExpiresAt, o.ExpiresAt.UTC().Format(time.RFC3339Nano))
	if o.ParentOperationID != "" {
		h.Set(HeaderParentOperationID, o.ParentOperationID)
	}
	return nil
}

// OriginFromHeaders checks shape only. Expiry is exposed for observability;
// authenticators enforce current validity, never backend header parsers.
func OriginFromHeaders(h http.Header) (*Origin, error) {
	values := make([]string, 4)
	present := false
	for i, name := range []string{HeaderOriginCaller, HeaderOperationID, HeaderParentOperationID, HeaderOriginExpiresAt} {
		value, found, err := singleCallerHeader(h, name)
		if err != nil || found && value == "" {
			return nil, ErrInvalidCaller
		}
		values[i] = value
		present = present || found
	}
	if !present {
		if _, found, err := singleCallerHeader(h, HeaderOriginAccount); err != nil || found {
			return nil, ErrInvalidCaller
		}
		return nil, nil
	}
	id, err := decodeCaller(values[0])
	if err != nil {
		return nil, err
	}
	expires, err := time.Parse(time.RFC3339Nano, values[3])
	if err != nil {
		return nil, ErrInvalidCaller
	}
	o := &Origin{Caller: id, OperationID: values[1], ParentOperationID: values[2], ExpiresAt: expires}
	value, found, err := singleCallerHeader(h, HeaderOriginAccount)
	if err != nil {
		return nil, err
	}
	if found {
		if len(value) > MaxCallerHeaderBytes {
			return nil, ErrInvalidCaller
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
			return nil, ErrInvalidCaller
		}
		o.Account = new(authntokens.AccountBinding)
		if httpx.ReadStrictJSON(&http.Request{Body: io.NopCloser(bytes.NewReader(raw))}, o.Account) != nil {
			return nil, ErrInvalidCaller
		}
	}
	if !validOrigin(o) {
		return nil, ErrInvalidCaller
	}
	return o, nil
}

func cloneOrigin(o *Origin) *Origin {
	if o == nil {
		return nil
	}
	copyOrigin := *o
	copyOrigin.Account = o.Account.Clone()
	if o.Caller != nil {
		principal := *o.Caller
		copyOrigin.Caller = &principal
	}
	return &copyOrigin
}
