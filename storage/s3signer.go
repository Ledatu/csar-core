package storage

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ledatu/csar-core/secret"
)

const (
	defaultS3Endpoint = "https://storage.yandexcloud.net"
	defaultS3Region   = "ru-central1"
)

// S3SignerConfig configures shared S3 presigning support.
type S3SignerConfig struct {
	Endpoint        string
	Region          string
	UsePathStyle    bool
	AccessKeyID     secret.Secret
	SecretAccessKey secret.Secret
}

// PresignPutInput describes a direct-upload request that should be signed.
type PresignPutInput struct {
	Bucket      string
	Key         string
	ContentType string
	Metadata    map[string]string
	Expires     time.Duration
}

// PresignGetInput describes a direct-download request that should be signed.
type PresignGetInput struct {
	Bucket              string
	Key                 string
	ResponseFilename    string
	ResponseContentType string
	Expires             time.Duration
}

// S3Signer issues presigned object-storage requests for direct client access.
type S3Signer struct {
	client *s3.PresignClient
}

// NewS3Signer creates a presigner backed by static S3 credentials.
func NewS3Signer(cfg S3SignerConfig) (*S3Signer, error) {
	if cfg.AccessKeyID.IsEmpty() || cfg.SecretAccessKey.IsEmpty() {
		return nil, fmt.Errorf("storage: presigning requires static access key credentials")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultS3Endpoint
	}
	if cfg.Region == "" {
		cfg.Region = defaultS3Region
	}

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(cfg.Endpoint),
		Region:       cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID.Plaintext(),
			cfg.SecretAccessKey.Plaintext(),
			"",
		),
		UsePathStyle: cfg.UsePathStyle,
	})

	return &S3Signer{
		client: s3.NewPresignClient(client),
	}, nil
}

// PresignPut signs a direct-upload request.
func (s *S3Signer) PresignPut(ctx context.Context, in PresignPutInput) (PresignedRequest, error) {
	if err := validateBucket(in.Bucket); err != nil {
		return PresignedRequest{}, err
	}
	if err := ValidateObjectKey(in.Key); err != nil {
		return PresignedRequest{}, err
	}
	if in.Expires <= 0 {
		return PresignedRequest{}, fmt.Errorf("storage: expires must be greater than zero")
	}

	contentType := strings.TrimSpace(in.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	out, err := s.client.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(in.Bucket),
		Key:         aws.String(in.Key),
		ContentType: aws.String(contentType),
		Metadata:    CanonicalMetadata(in.Metadata),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = in.Expires
	})
	if err != nil {
		return PresignedRequest{}, fmt.Errorf("storage: presign put: %w", err)
	}

	return PresignedRequest{
		Method:    http.MethodPut,
		URL:       out.URL,
		Headers:   flattenHeader(out.SignedHeader),
		ExpiresAt: time.Now().UTC().Add(in.Expires),
	}, nil
}

// PresignGet signs a direct-download request.
func (s *S3Signer) PresignGet(ctx context.Context, in PresignGetInput) (PresignedRequest, error) {
	if err := validateBucket(in.Bucket); err != nil {
		return PresignedRequest{}, err
	}
	if err := ValidateObjectKey(in.Key); err != nil {
		return PresignedRequest{}, err
	}
	if in.Expires <= 0 {
		return PresignedRequest{}, fmt.Errorf("storage: expires must be greater than zero")
	}

	req := &s3.GetObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
	}
	if ct := strings.TrimSpace(in.ResponseContentType); ct != "" {
		req.ResponseContentType = aws.String(ct)
	}
	if filename := strings.TrimSpace(in.ResponseFilename); filename != "" {
		req.ResponseContentDisposition = aws.String(contentDispositionAttachment(filename))
	}

	out, err := s.client.PresignGetObject(ctx, req, func(opts *s3.PresignOptions) {
		opts.Expires = in.Expires
	})
	if err != nil {
		return PresignedRequest{}, fmt.Errorf("storage: presign get: %w", err)
	}

	return PresignedRequest{
		Method:    http.MethodGet,
		URL:       out.URL,
		Headers:   flattenHeader(out.SignedHeader),
		ExpiresAt: time.Now().UTC().Add(in.Expires),
	}, nil
}

func flattenHeader(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}

	out := make(map[string]string, len(header))
	for key, values := range header {
		out[key] = strings.Join(values, ", ")
	}
	return out
}

func contentDispositionAttachment(filename string) string {
	safe := strings.NewReplacer(`\`, "_", `"`, "_", "\r", "_", "\n", "_").Replace(filename)
	return fmt.Sprintf("attachment; filename=%q", safe)
}
