package email

import (
	"context"
	"errors"
	"net/http"

	"github.com/ledatu/csar-core/postbox"
)

// NewSender constructs the selected transport without sending a message.
func NewSender(cfg Config, client *http.Client) (Sender, error) {
	if cfg.Postbox != nil {
		pb := *cfg.Postbox
		cfg.Postbox = &pb
	}
	if cfg.Selectel != nil {
		smtpCfg := *cfg.Selectel
		cfg.Selectel = &smtpCfg
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate("email.delivery"); err != nil {
		return nil, err
	}
	if cfg.Provider == ProviderSelectel {
		return newSMTP(cfg.Selectel), nil
	}
	c, err := postbox.NewClient(cfg.Postbox, client)
	if err != nil {
		return nil, err
	}
	return &postboxSender{client: c}, nil
}

type postboxSender struct{ client *postbox.Client }

func (s *postboxSender) Send(ctx context.Context, msg *Message) (Receipt, error) {
	m, _, _, err := prepare(msg)
	if err != nil {
		return Receipt{}, err
	}
	id, err := s.client.SendEmailWithReceipt(ctx, &postbox.Message{FromEmailAddress: m.From, ToAddresses: []string{m.To}, Subject: m.Subject, TextBody: m.TextBody, HTMLBody: m.HTMLBody})
	if err != nil {
		outcome := Unknown
		var pe *postbox.SendError
		if errors.As(err, &pe) {
			outcome = Rejected
			if pe.Unknown {
				outcome = Unknown
			} else if pe.Retryable {
				outcome = Retryable
			}
			return Receipt{}, failure(pe.Stage, outcome, pe.StatusCode)
		}
		return Receipt{}, failure("postbox", outcome, 0)
	}
	return Receipt{Provider: ProviderPostbox, MessageID: id}, nil
}
