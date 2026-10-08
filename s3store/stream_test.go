package s3store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ledatu/csar-core/secret"
	"github.com/ledatu/csar-core/ycloud"
)

func TestVersionedStreamBothAuthModes(t *testing.T) {
	for _, mode := range []string{"static", "iam_token"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte("archive content"), 100)
			wrongVersion := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/test-bucket/audit/data" {
					t.Error("unexpected object path", r.URL.Path)
				}
				if mode == "iam_token" && r.Header.Get("X-YaCloud-SubjectToken") != "local-test-token" {
					t.Error("IAM auth missing")
				}
				switch r.Method {
				case http.MethodPut:
					body, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(body, payload) {
						t.Error("upload changed bytes", err)
					}
					if r.ContentLength != int64(len(payload)) {
						t.Error("upload size not explicit")
					}
					w.Header().Set("x-amz-version-id", "pinned+version/1")
				case http.MethodGet:
					if r.URL.Query().Get("versionId") != "pinned+version/1" {
						t.Error("version not requested")
					}
					version := "pinned+version/1"
					if wrongVersion {
						version = "latest"
					}
					w.Header().Set("x-amz-version-id", version)
					_, _ = w.Write(payload)
				default:
					t.Error("unexpected operation", r.Method)
				}
			}))
			defer server.Close()
			client, err := NewClient(&Config{Bucket: "test-bucket", Endpoint: server.URL, Region: "test", Auth: ycloud.AuthConfig{AuthMode: mode, AccessKeyID: secret.NewSecret("local-test-key"), SecretAccessKey: secret.NewSecret("local-test-secret"), IAMToken: secret.NewSecret("local-test-token")}}, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			ref, err := client.PutStream(context.Background(), "audit/data", bytes.NewReader(payload), int64(len(payload)), "application/gzip")
			if err != nil || ref.VersionID != "pinned+version/1" {
				t.Fatalf("missing version receipt: %+v %v", ref, err)
			}
			reader, err := client.OpenVersion(context.Background(), "audit/data", ref.VersionID, int64(len(payload)))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil || !bytes.Equal(body, payload) {
				t.Fatal("pinned bytes changed", err)
			}
			wrongVersion = true
			if reader, err := client.OpenVersion(context.Background(), "audit/data", ref.VersionID, int64(len(payload))); err == nil {
				_ = reader.Close()
				t.Fatal("provider ignored version but read succeeded")
			}
		})
	}
}

func TestStreamBoundsRejectTruncationAndUnknownLengthOverflow(t *testing.T) {
	client := &Client{}
	for _, size := range []int64{0, MaxStreamObjectBytes + 1, 4} {
		if _, err := client.PutStream(context.Background(), "data", bytes.NewReader([]byte("abc")), size, "x"); err == nil {
			t.Fatal("invalid upload size accepted")
		}
	}
	for _, body := range []string{"abcd", "abc"} {
		reader := &boundedObjectReader{ReadCloser: io.NopCloser(bytes.NewBufferString(body)), remaining: 3, cancel: func() {}}
		bytes, err := io.ReadAll(reader)
		_ = reader.Close()
		if body == "abcd" && err == nil {
			t.Fatal("unknown-length overflow silently truncated")
		}
		if body == "abc" && (err != nil || string(bytes) != body) {
			t.Fatal("exact-length body failed", err)
		}
	}
}

func TestConditionalArchiveReplayDoesNotCreateNewVersions(t *testing.T) {
	for _, mode := range []string{"static", "iam_token"} {
		t.Run(mode, func(t *testing.T) {
			payload := []byte("one stable archive body")
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/test-bucket/prefix/audit/data" {
					t.Error("prefix join changed", r.URL.Path)
				}
				if r.Method == http.MethodPut {
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("conditional PUT missing")
					}
					if writes > 0 {
						w.WriteHeader(http.StatusPreconditionFailed)
						_, _ = w.Write([]byte(`<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>`))
						return
					}
					writes++
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("x-amz-version-id", "original-version")
					return
				}
				if r.Method != http.MethodHead {
					t.Error("unexpected operation", r.Method)
				}
				w.Header().Set("x-amz-version-id", "original-version")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			}))
			defer server.Close()
			c, err := NewClient(&Config{Bucket: "test-bucket", Endpoint: server.URL, Region: "test", Prefix: "prefix", Auth: ycloud.AuthConfig{AuthMode: mode, AccessKeyID: secret.NewSecret("local-test-key"), SecretAccessKey: secret.NewSecret("local-test-secret"), IAMToken: secret.NewSecret("local-test-token")}}, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			ref, err := c.PutStreamIfAbsent(context.Background(), "audit/data", bytes.NewReader(payload), int64(len(payload)), "application/gzip")
			if err != nil || ref.VersionID != "original-version" {
				t.Fatal("initial receipt failed", err)
			}
			if _, err := c.PutStreamIfAbsent(context.Background(), "audit/data", bytes.NewReader(payload), int64(len(payload)), "application/gzip"); !errors.Is(err, ErrObjectExists) {
				t.Fatal("existing object overwritten", err)
			}
			stat, err := c.StatStreamObject(context.Background(), "audit/data")
			if err != nil || stat.VersionID != ref.VersionID || stat.Size != int64(len(payload)) || writes != 1 {
				t.Fatal("retry created a new version or lost pinned metadata", err)
			}
		})
	}
}
