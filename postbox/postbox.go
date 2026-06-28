// Package postbox provides a thin Yandex Cloud Postbox HTTP client.
package postbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-core/ycloud"
)

const (
	// DefaultEndpoint is the documented Yandex Cloud Postbox endpoint.
	DefaultEndpoint = "https://postbox.cloud.yandex.net"
	// DefaultRegion is the documented Postbox region for request metadata.
	DefaultRegion  = "ru-central1"
	defaultCharset = "UTF-8"
)

// Config controls outbound mail delivery through Yandex Cloud Postbox.
type Config struct {
	Endpoint string            `yaml:"endpoint"`
	Region   string            `yaml:"region"`
	Auth     ycloud.AuthConfig `yaml:"auth"`
}

// ApplyDefaults fills default endpoint and region in place.
func (c *Config) ApplyDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	if c.Region == "" {
		c.Region = DefaultRegion
	}
}

// Validate checks that the Postbox config is complete without opening files or making network calls.
func (c *Config) Validate(prefix string) error {
	if c.Endpoint == "" {
		return fmt.Errorf("%s.endpoint is required", prefix)
	}
	if c.Region == "" {
		return fmt.Errorf("%s.region is required", prefix)
	}
	switch c.Auth.AuthMode {
	case "iam_token":
		if c.Auth.IAMToken.IsEmpty() {
			return fmt.Errorf("%s.auth.iam_token is required when auth_mode=iam_token", prefix)
		}
	case "oauth_token":
		if c.Auth.OAuthToken.IsEmpty() {
			return fmt.Errorf("%s.auth.oauth_token is required when auth_mode=oauth_token", prefix)
		}
	case "metadata":
	case "service_account":
		if c.Auth.SAKeyFile == "" {
			return fmt.Errorf("%s.auth.sa_key_file is required when auth_mode=service_account", prefix)
		}
	default:
		return fmt.Errorf("%s.auth.auth_mode must be iam_token, oauth_token, metadata, or service_account", prefix)
	}
	return nil
}

// Message is a simple email payload for Postbox.
type Message struct {
	FromEmailAddress string
	ToAddresses      []string
	Subject          string
	TextBody         string
	HTMLBody         string
	Charset          string
}

// TokenResolver resolves Yandex Cloud IAM tokens.
type TokenResolver interface {
	ResolveToken(ctx context.Context) (string, error)
}

// Client sends email through the Yandex Cloud Postbox HTTP API.
type Client struct {
	endpoint     string
	client       *http.Client
	tokenResolve TokenResolver
}

// NewClient creates a Postbox client using the shared Yandex Cloud IAM resolver.
func NewClient(cfg *Config, client *http.Client) (*Client, error) {
	cfg.ApplyDefaults()
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resolver, err := ycloud.NewIAMTokenResolver(&cfg.Auth, client)
	if err != nil {
		return nil, fmt.Errorf("initializing postbox IAM resolver: %w", err)
	}
	return NewClientWithResolver(cfg, client, resolver), nil
}

// NewClientWithResolver creates a client with an explicit token resolver for tests.
func NewClientWithResolver(cfg *Config, client *http.Client, resolver TokenResolver) *Client {
	cfg.ApplyDefaults()
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		client:       client,
		tokenResolve: resolver,
	}
}

// SendEmail sends a plain Postbox message.
func (c *Client) SendEmail(ctx context.Context, msg *Message) error {
	token, err := c.tokenResolve.ResolveToken(ctx)
	if err != nil {
		return fmt.Errorf("resolving postbox IAM token: %w", err)
	}
	body, err := json.Marshal(toSendEmailRequest(msg))
	if err != nil {
		return fmt.Errorf("building postbox email request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v2/email/outbound-emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building postbox HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-YaCloud-SubjectToken", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending postbox email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("postbox send failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func toSendEmailRequest(msg *Message) sendEmailRequest {
	charset := msg.Charset
	if charset == "" {
		charset = defaultCharset
	}
	return sendEmailRequest{
		FromEmailAddress: msg.FromEmailAddress,
		Destination: destination{
			ToAddresses: msg.ToAddresses,
		},
		Content: emailContent{
			Simple: message{
				Subject: content{
					Data:    msg.Subject,
					Charset: charset,
				},
				Body: body{
					Text: content{
						Data:    msg.TextBody,
						Charset: charset,
					},
					HTML: content{
						Data:    msg.HTMLBody,
						Charset: charset,
					},
				},
			},
		},
	}
}

type sendEmailRequest struct {
	FromEmailAddress string       `json:"FromEmailAddress"`
	Destination      destination  `json:"Destination"`
	Content          emailContent `json:"Content"`
}

type destination struct {
	ToAddresses []string `json:"ToAddresses"`
}

type emailContent struct {
	Simple message `json:"Simple"`
}

type message struct {
	Subject content `json:"Subject"`
	Body    body    `json:"Body"`
}

type body struct {
	Text content `json:"Text"`
	HTML content `json:"Html"`
}

type content struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset"`
}
