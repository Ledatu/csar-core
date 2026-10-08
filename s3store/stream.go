package s3store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/ledatu/csar-core/storage"
)

// MaxStreamObjectBytes bounds the streaming API separately from token reads.
const MaxStreamObjectBytes int64 = 64 << 20

// PutStream writes a known-length seekable body without materializing it. The
// caller owns content hashing; a version receipt/ETag is not an integrity proof.
// The body must remain unchanged throughout this synchronous operation.
func (c *Client) PutStream(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) (storage.ObjectRef, error) {
	return c.putStream(ctx, key, body, size, contentType, false)
}

// ErrObjectExists identifies a conditional-write conflict; callers must verify
// the existing pinned version rather than overwriting it.
var ErrObjectExists = errors.New("s3store: conditional object already exists")

// PutStreamIfAbsent uses If-None-Match: * so a lost receipt/retry cannot generate
// unlimited object versions. The configured store must support conditional PUT.
func (c *Client) PutStreamIfAbsent(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) (storage.ObjectRef, error) {
	return c.putStream(ctx, key, body, size, contentType, true)
}

func (c *Client) putStream(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string, ifAbsent bool) (storage.ObjectRef, error) {
	if body == nil || size < 1 || size > MaxStreamObjectBytes {
		return storage.ObjectRef{}, errors.New("s3store: invalid stream size/body")
	}
	key, err := storage.JoinObjectKey(c.cfg.Prefix, key)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	actual, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	if actual != size {
		return storage.ObjectRef{}, errors.New("s3store: stream length mismatch")
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return storage.ObjectRef{}, err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ref := storage.ObjectRef{Bucket: c.cfg.Bucket, Key: key, Size: size, ContentType: contentType}
	if !c.iamAuth {
		input := &s3.PutObjectInput{Bucket: aws.String(c.cfg.Bucket), Key: aws.String(key), Body: body, ContentLength: aws.Int64(size), ContentType: aws.String(contentType)}
		if ifAbsent {
			input.IfNoneMatch = aws.String("*")
		}
		resp, err := c.s3Client.PutObject(ctx, input)
		if err != nil && ifAbsent {
			var responseErr *smithyhttp.ResponseError
			if errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusPreconditionFailed {
				return storage.ObjectRef{}, ErrObjectExists
			}
		}
		if err != nil {
			return storage.ObjectRef{}, err
		}
		ref.VersionID = aws.ToString(resp.VersionId)
		ref.ETag = aws.ToString(resp.ETag)
		return ref, nil
	}
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	objectURL, err := c.objectURL(key)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, objectURL, io.LimitReader(body, size))
	if err != nil {
		return storage.ObjectRef{}, err
	}
	if ifAbsent {
		req.Header.Set("If-None-Match", "*")
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-YaCloud-SubjectToken", token)
	resp, err := noRedirectClient(c.httpClient).Do(req)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if ifAbsent && resp.StatusCode == http.StatusPreconditionFailed {
		return storage.ObjectRef{}, ErrObjectExists
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return storage.ObjectRef{}, fmt.Errorf("s3store: stream upload HTTP %d", resp.StatusCode)
	}
	ref.VersionID = resp.Header.Get("x-amz-version-id")
	ref.ETag = resp.Header.Get("ETag")
	return ref, nil
}

// OpenVersion requires an exact non-null version receipt and returns a bounded
// stream. The reader must be closed. A provider ignoring VersionId is rejected.
func (c *Client) OpenVersion(ctx context.Context, key, version string, maxBytes int64) (io.ReadCloser, error) {
	if version == "" || version == "null" || maxBytes < 1 || maxBytes > MaxStreamObjectBytes {
		return nil, errors.New("s3store: pinned version and bounded size required")
	}
	key, err := storage.JoinObjectKey(c.cfg.Prefix, key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	var body io.ReadCloser
	var length int64 = -1
	var received string
	if !c.iamAuth {
		resp, getErr := c.s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.cfg.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
		if getErr != nil {
			cancel()
			return nil, getErr
		}
		body = resp.Body
		received = aws.ToString(resp.VersionId)
		if resp.ContentLength != nil {
			length = *resp.ContentLength
		}
	} else {
		body, length, received, err = c.openVersionIAM(ctx, key, version)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if received != version || length > maxBytes {
		_ = body.Close()
		cancel()
		return nil, errors.New("s3store: version mismatch or oversized download")
	}
	return &boundedObjectReader{ReadCloser: body, remaining: maxBytes, cancel: cancel}, nil
}

func (c *Client) openVersionIAM(ctx context.Context, key, version string) (io.ReadCloser, int64, string, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return nil, 0, "", err
	}
	objectURL, err := c.objectURL(key)
	if err != nil {
		return nil, 0, "", err
	}
	u, err := url.Parse(objectURL)
	if err != nil {
		return nil, 0, "", err
	}
	q := u.Query()
	q.Set("versionId", version)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)
	resp, err := noRedirectClient(c.httpClient).Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, 0, "", fmt.Errorf("s3store: pinned download HTTP %d", resp.StatusCode)
	}
	return resp.Body, resp.ContentLength, resp.Header.Get("x-amz-version-id"), nil
}

type boundedObjectReader struct {
	io.ReadCloser
	remaining int64
	cancel    context.CancelFunc
}

func (r *boundedObjectReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errors.New("s3store: download exceeds byte budget")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	return n, err
}
func (r *boundedObjectReader) Close() error {
	r.cancel()
	return r.ReadCloser.Close()
}

// Subject-token headers must never follow redirects to another endpoint.
func noRedirectClient(client *http.Client) *http.Client {
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &bounded
}

// StatStreamObject shares the validated key/prefix semantics of Put/OpenStream.
func (c *Client) StatStreamObject(ctx context.Context, key string) (storage.ObjectRef, error) {
	key, err := storage.JoinObjectKey(c.cfg.Prefix, key)
	if err != nil {
		return storage.ObjectRef{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.iamAuth {
		return c.statObjectIAM(ctx, key, key)
	}
	return c.statObjectSDK(ctx, key, key)
}
