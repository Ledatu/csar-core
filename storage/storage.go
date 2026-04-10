package storage

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ObjectRef describes an object stored in the backing bucket.
type ObjectRef struct {
	Scope        string     `json:"scope,omitempty"`
	Bucket       string     `json:"bucket"`
	Key          string     `json:"key"`
	ETag         string     `json:"etag,omitempty"`
	VersionID    string     `json:"version_id,omitempty"`
	ContentType  string     `json:"content_type,omitempty"`
	Size         int64      `json:"size,omitempty"`
	LastModified *time.Time `json:"last_modified,omitempty"`
}

// ObjectInfo preserves the shared object metadata name already used in csar-core.
type ObjectInfo = ObjectRef

// PresignedRequest represents a signed HTTP request clients can execute directly.
type PresignedRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// SignedRequest preserves the shared request name already used in csar-core.
type SignedRequest = PresignedRequest

// ReadLink captures a signed read request for an already uploaded object.
type ReadLink struct {
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// UploadIntentStatus captures the current lifecycle state of an upload intent.
type UploadIntentStatus string

const (
	UploadIntentStatusPending   UploadIntentStatus = "pending"
	UploadIntentStatusFinalized UploadIntentStatus = "finalized"
	UploadIntentStatusExpired   UploadIntentStatus = "expired"
)

// UploadIntent records the presigned upload plus the object metadata it targets.
type UploadIntent struct {
	ID            string             `json:"id"`
	Scope         string             `json:"scope,omitempty"`
	Status        UploadIntentStatus `json:"status"`
	Object        ObjectInfo         `json:"object"`
	ContentLength int64              `json:"content_length"`
	Metadata      map[string]string  `json:"metadata,omitempty"`
	Upload        SignedRequest      `json:"upload"`
	CreatedAt     time.Time          `json:"created_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	FinalizedAt   *time.Time         `json:"finalized_at,omitempty"`
}

// MintUploadIntentInput is the shared request shape for creating an upload intent.
type MintUploadIntentInput struct {
	Scope         string
	Filename      string
	ContentType   string
	ContentLength int64
	Metadata      map[string]string
	TTL           time.Duration
}

// IssueReadLinkInput is the shared request shape for creating a signed read link.
type IssueReadLinkInput struct {
	Bucket              string
	Key                 string
	ResponseFilename    string
	ResponseContentType string
	TTL                 time.Duration
}

// NewUploadIntentID returns a stable prefix so logs are easy to grep.
func NewUploadIntentID() string {
	return "ui_" + uuid.NewString()
}

// ValidateMintUploadIntentInput validates the shared upload-intent fields.
func ValidateMintUploadIntentInput(in MintUploadIntentInput) error {
	if err := ValidateScopeName(in.Scope); err != nil {
		return err
	}
	if strings.TrimSpace(in.ContentType) == "" {
		return fmt.Errorf("storage: content type is required")
	}
	if in.ContentLength <= 0 {
		return fmt.Errorf("storage: content length must be greater than zero")
	}
	if in.TTL <= 0 {
		return fmt.Errorf("storage: ttl must be greater than zero")
	}
	return nil
}

// ValidateIssueReadLinkInput validates the shared signed-read fields.
func ValidateIssueReadLinkInput(in IssueReadLinkInput) error {
	if err := validateBucket(in.Bucket); err != nil {
		return err
	}
	if err := ValidateObjectKey(in.Key); err != nil {
		return err
	}
	if in.TTL <= 0 {
		return fmt.Errorf("storage: ttl must be greater than zero")
	}
	return nil
}

// JoinObjectKey joins an optional prefix with a relative object key.
func JoinObjectKey(prefix, key string) (string, error) {
	if err := ValidateObjectKey(key); err != nil {
		return "", err
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return key, nil
	}
	if err := ValidateObjectKey(prefix); err != nil {
		return "", fmt.Errorf("storage: invalid prefix: %w", err)
	}
	return prefix + "/" + key, nil
}

// ValidateScopeName ensures a logical storage scope name is non-empty and stable.
func ValidateScopeName(scope string) error {
	if !utf8.ValidString(scope) {
		return fmt.Errorf("storage: scope must be valid UTF-8")
	}

	scope = strings.TrimSpace(scope)
	if scope == "" {
		return fmt.Errorf("storage: scope is required")
	}
	if strings.Contains(scope, "/") {
		return fmt.Errorf("storage: scope must not contain '/'")
	}
	for _, r := range scope {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("storage: scope must not contain whitespace or control characters")
		}
	}
	return nil
}

// ValidateObjectKey ensures the key is a clean relative path.
func ValidateObjectKey(key string) error {
	if !utf8.ValidString(key) {
		return fmt.Errorf("storage: object key must be valid UTF-8")
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("storage: object key is required")
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return fmt.Errorf("storage: object key must not start or end with '/'")
	}

	for _, segment := range strings.Split(key, "/") {
		if segment == "" {
			return fmt.Errorf("storage: object key must not contain empty path segments")
		}
		if segment == "." || segment == ".." {
			return fmt.Errorf("storage: object key must not contain dot path segments")
		}
		for _, r := range segment {
			if unicode.IsControl(r) {
				return fmt.Errorf("storage: object key must not contain control characters")
			}
		}
	}

	return nil
}

// CanonicalMetadata lowercases keys, trims whitespace, and drops empty entries.
func CanonicalMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}

	out := make(map[string]string, len(metadata))
	for k, v := range metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateBucket(bucket string) error {
	if strings.TrimSpace(bucket) == "" {
		return fmt.Errorf("storage: bucket is required")
	}
	return nil
}
