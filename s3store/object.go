package s3store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/ledatu/csar-core/storage"
)

var (
	// ErrObjectNotFound lets callers map missing object lookups without relying on strings.
	ErrObjectNotFound = errors.New("s3store: object not found")
	// ErrSigningUnsupported is returned when the configured auth mode cannot mint presigned URLs.
	ErrSigningUnsupported = errors.New("s3store: signing unsupported")
)

// PutObjectOptions controls object writes beyond the raw body bytes.
type PutObjectOptions struct {
	ContentType string
}

// PresignPutOptions controls a client-upload presigned PUT operation.
type PresignPutOptions struct {
	ExpiresIn              time.Duration
	ContentType            string
	ChecksumSHA256Base64   string
}

// PresignGetOptions controls a presigned GET operation.
type PresignGetOptions struct {
	ExpiresIn                  time.Duration
	ResponseContentType        string
	ResponseContentDisposition string
}

// StatObject reads object metadata without downloading the full body.
func (c *Client) StatObject(ctx context.Context, tokenRef string) (storage.ObjectInfo, error) {
	key := c.cfg.Prefix + tokenRef
	if c.iamAuth {
		return c.statObjectIAM(ctx, key, tokenRef)
	}
	return c.statObjectSDK(ctx, key, tokenRef)
}

// PresignPutObject mints a signed PUT request for a caller-managed upload.
func (c *Client) PresignPutObject(ctx context.Context, tokenRef string, opts PresignPutOptions) (*storage.SignedRequest, error) {
	if c.presignClient == nil {
		return nil, ErrSigningUnsupported
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.cfg.Bucket),
		Key:         aws.String(c.cfg.Prefix + tokenRef),
		ContentType: aws.String(defaultContentType(opts.ContentType)),
	}
	if opts.ChecksumSHA256Base64 != "" {
		input.ChecksumSHA256 = aws.String(opts.ChecksumSHA256Base64)
	}

	req, err := c.presignClient.PresignPutObject(ctx, input, func(o *s3.PresignOptions) {
		o.Expires = opts.ExpiresIn
	})
	if err != nil {
		return nil, fmt.Errorf("s3store: presign put %q: %w", tokenRef, err)
	}

	return &storage.SignedRequest{
		Method:    http.MethodPut,
		URL:       req.URL,
		Headers:   signedHeaders(req.SignedHeader),
		ExpiresAt: time.Now().UTC().Add(opts.ExpiresIn),
	}, nil
}

// PresignGetObject mints a signed GET request for a stored object.
func (c *Client) PresignGetObject(ctx context.Context, tokenRef string, opts PresignGetOptions) (*storage.ReadLink, error) {
	if c.presignClient == nil {
		return nil, ErrSigningUnsupported
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(c.cfg.Bucket),
		Key:    aws.String(c.cfg.Prefix + tokenRef),
	}
	if opts.ResponseContentType != "" {
		input.ResponseContentType = aws.String(opts.ResponseContentType)
	}
	if opts.ResponseContentDisposition != "" {
		input.ResponseContentDisposition = aws.String(opts.ResponseContentDisposition)
	}

	req, err := c.presignClient.PresignGetObject(ctx, input, func(o *s3.PresignOptions) {
		o.Expires = opts.ExpiresIn
	})
	if err != nil {
		return nil, fmt.Errorf("s3store: presign get %q: %w", tokenRef, err)
	}

	return &storage.ReadLink{
		URL:       req.URL,
		Headers:   signedHeaders(req.SignedHeader),
		ExpiresAt: time.Now().UTC().Add(opts.ExpiresIn),
	}, nil
}

func (c *Client) statObjectSDK(ctx context.Context, key, tokenRef string) (storage.ObjectInfo, error) {
	resp, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var responseErr *smithyhttp.ResponseError
		if errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusNotFound {
			return storage.ObjectInfo{}, fmt.Errorf("s3store: object %q: %w", key, ErrObjectNotFound)
		}
		return storage.ObjectInfo{}, fmt.Errorf("s3store: stat object %q: %w", key, err)
	}

	var lastModified *time.Time
	if resp.LastModified != nil {
		ts := *resp.LastModified
		lastModified = &ts
	}

	return storage.ObjectInfo{
		Bucket:       c.cfg.Bucket,
		Key:          tokenRef,
		ETag:         aws.ToString(resp.ETag),
		Size:         aws.ToInt64(resp.ContentLength),
		ContentType:  aws.ToString(resp.ContentType),
		LastModified: lastModified,
	}, nil
}

func (c *Client) statObjectIAM(ctx context.Context, key, tokenRef string) (storage.ObjectInfo, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return storage.ObjectInfo{}, fmt.Errorf("s3store: auth: %w", err)
	}

	reqURL, err := c.objectURL(key)
	if err != nil {
		return storage.ObjectInfo{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return storage.ObjectInfo{}, fmt.Errorf("s3store: build head request: %w", err)
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return storage.ObjectInfo{}, fmt.Errorf("s3store: head %q HTTP: %w", key, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return storage.ObjectInfo{}, fmt.Errorf("s3store: object %q: %w", key, ErrObjectNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return storage.ObjectInfo{}, fmt.Errorf("s3store: head %q: HTTP %d: %s", key, resp.StatusCode, string(b))
	}

	size := int64(0)
	if header := resp.Header.Get("Content-Length"); header != "" {
		parsed, parseErr := strconv.ParseInt(header, 10, 64)
		if parseErr != nil {
			return storage.ObjectInfo{}, fmt.Errorf("s3store: parse content-length for %q: %w", key, parseErr)
		}
		size = parsed
	}

	var lastModified *time.Time
	if header := resp.Header.Get("Last-Modified"); header != "" {
		parsed, parseErr := time.Parse(http.TimeFormat, header)
		if parseErr != nil {
			return storage.ObjectInfo{}, fmt.Errorf("s3store: parse last-modified for %q: %w", key, parseErr)
		}
		lastModified = &parsed
	}

	return storage.ObjectInfo{
		Bucket:       c.cfg.Bucket,
		Key:          tokenRef,
		ETag:         resp.Header.Get("ETag"),
		Size:         size,
		ContentType:  resp.Header.Get("Content-Type"),
		LastModified: lastModified,
	}, nil
}

func defaultContentType(value string) string {
	if strings.TrimSpace(value) == "" {
		return "application/octet-stream"
	}
	return strings.TrimSpace(value)
}

func signedHeaders(headers http.Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[key] = strings.Join(values, ",")
	}
	return out
}
