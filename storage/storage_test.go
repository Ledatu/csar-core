package storage

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/secret"
)

func TestValidateObjectKey(t *testing.T) {
	t.Parallel()

	valid := []string{
		"avatar.png",
		"tenant-a/avatars/user-1.png",
		"nested/path/file.txt",
	}
	for _, key := range valid {
		if err := ValidateObjectKey(key); err != nil {
			t.Fatalf("ValidateObjectKey(%q) unexpected error: %v", key, err)
		}
	}

	invalid := []string{
		"",
		"/rooted",
		"trailing/",
		"double//slash",
		"../escape",
		"dot/./segment",
	}
	for _, key := range invalid {
		if err := ValidateObjectKey(key); err == nil {
			t.Fatalf("ValidateObjectKey(%q) expected error", key)
		}
	}
}

func TestJoinObjectKey(t *testing.T) {
	t.Parallel()

	joined, err := JoinObjectKey("uploads/private", "tenant-a/file.txt")
	if err != nil {
		t.Fatalf("JoinObjectKey returned error: %v", err)
	}
	if joined != "uploads/private/tenant-a/file.txt" {
		t.Fatalf("unexpected joined key %q", joined)
	}
}

func TestCanonicalMetadata(t *testing.T) {
	t.Parallel()

	got := CanonicalMetadata(map[string]string{
		strings.Join([]string{"", "X-Tenant", ""}, " "): " tenant-a ",
		"": "ignored",
	})
	if got["x-tenant"] != "tenant-a" {
		t.Fatalf("expected canonicalized metadata, got %#v", got)
	}
	if _, ok := got[""]; ok {
		t.Fatalf("empty key should be dropped: %#v", got)
	}
}

func TestValidateScopeName(t *testing.T) {
	t.Parallel()

	valid := []string{"avatar", "profile-images", "scope.v2"}
	for _, scope := range valid {
		if err := ValidateScopeName(scope); err != nil {
			t.Fatalf("ValidateScopeName(%q) unexpected error: %v", scope, err)
		}
	}

	invalid := []string{"", "avatar/profile", "two words", "line\nbreak"}
	for _, scope := range invalid {
		if err := ValidateScopeName(scope); err == nil {
			t.Fatalf("ValidateScopeName(%q) expected error", scope)
		}
	}
}

func TestS3SignerPresignsRequests(t *testing.T) {
	t.Parallel()

	signer, err := NewS3Signer(S3SignerConfig{
		Endpoint:        "https://storage.example.test",
		Region:          "ru-central1",
		UsePathStyle:    true,
		AccessKeyID:     secret.NewSecret("test-access"),
		SecretAccessKey: secret.NewSecret("test-secret"),
	})
	if err != nil {
		t.Fatalf("NewS3Signer returned error: %v", err)
	}

	putReq, err := signer.PresignPut(context.Background(), PresignPutInput{
		Bucket:      "media",
		Key:         "tenant-a/avatar.png",
		ContentType: "image/png",
		Metadata: map[string]string{
			"Trace-ID": "abc123",
		},
		Expires: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("PresignPut returned error: %v", err)
	}
	if putReq.Method != "PUT" {
		t.Fatalf("unexpected method %q", putReq.Method)
	}
	if !strings.Contains(putReq.URL, "X-Amz-Algorithm=") {
		t.Fatalf("expected signed URL, got %q", putReq.URL)
	}
	if meta := putReq.Headers["X-Amz-Meta-Trace-Id"]; meta != "abc123" {
		t.Fatalf("expected signed metadata header, got %#v", putReq.Headers)
	}

	getReq, err := signer.PresignGet(context.Background(), PresignGetInput{
		Bucket:              "media",
		Key:                 "tenant-a/avatar.png",
		ResponseFilename:    "avatar.png",
		ResponseContentType: "image/png",
		Expires:             5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("PresignGet returned error: %v", err)
	}
	if getReq.Method != "GET" {
		t.Fatalf("unexpected method %q", getReq.Method)
	}
	parsed, err := url.Parse(getReq.URL)
	if err != nil {
		t.Fatalf("Parse signed URL: %v", err)
	}
	if parsed.Query().Get("X-Amz-Algorithm") == "" {
		t.Fatalf("expected signed URL query params, got %q", getReq.URL)
	}
}
