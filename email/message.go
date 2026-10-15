package email

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Message has one recipient so one submission cannot partially accept a batch.
type Message struct {
	From     string
	To       string
	Subject  string
	TextBody string
	HTMLBody string
	// ID is the SMTP Message-ID, including angle brackets. Postbox Simple mail
	// uses a provider-assigned ID instead. Neither guarantees deduplication.
	ID string
}

// Receipt confirms transport acceptance, not delivery to the recipient inbox.
type Receipt struct {
	Provider  string
	MessageID string
}

// Sender is the transport selection boundary used by service-owned templates.
type Sender interface {
	Send(context.Context, *Message) (Receipt, error)
}

func prepare(msg *Message) (Message, *mail.Address, *mail.Address, error) {
	if msg == nil {
		return Message{}, nil, nil, failure("validate", Rejected, 0)
	}
	m := *msg
	if strings.ContainsAny(m.From+m.To+m.Subject+m.ID, "\r\n\x00") || len(m.Subject) > 256 || strings.TrimSpace(m.Subject) == "" || len(m.TextBody)+len(m.HTMLBody) > 1024*1024 || m.TextBody == "" && m.HTMLBody == "" {
		return Message{}, nil, nil, failure("validate", Rejected, 0)
	}
	from, err := mail.ParseAddress(m.From)
	if err != nil || !validAddress(from) {
		return Message{}, nil, nil, failure("sender", Rejected, 0)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil || !validAddress(to) {
		return Message{}, nil, nil, failure("recipient", Rejected, 0)
	}
	if m.ID == "" {
		m.ID = "<" + uuid.NewString() + "@" + strings.SplitN(from.Address, "@", 2)[1] + ">"
	}
	if !validID(m.ID) {
		return Message{}, nil, nil, failure("message_id", Rejected, 0)
	}
	m.From, m.To = from.String(), to.String()
	return m, from, to, nil
}

func validAddress(a *mail.Address) bool {
	return a != nil && len(a.Address) <= 254 && len(a.Name) <= 128 && strings.Count(a.Address, "@") == 1 && !strings.ContainsAny(a.Address, "\r\n\x00")
}

func validID(id string) bool {
	if len(id) < 5 || len(id) > 254 || id[0] != '<' || id[len(id)-1] != '>' {
		return false
	}
	inner := id[1 : len(id)-1]
	return strings.Count(inner, "@") == 1 && !strings.ContainsAny(inner, "<> \t\r\n") && ascii(inner)
}

func ascii(s string) bool {
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func mimeMessage(m *Message) ([]byte, error) {
	var b bytes.Buffer
	_, _ = fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\n", m.From, m.To, mime.BEncoding.Encode("UTF-8", m.Subject), time.Now().UTC().Format(time.RFC1123Z), m.ID)
	w := multipart.NewWriter(&b)
	_, _ = fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", w.Boundary())
	for _, part := range []struct{ kind, body string }{{"text/plain", m.TextBody}, {"text/html", m.HTMLBody}} {
		if part.body == "" {
			continue
		}
		p, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {part.kind + "; charset=UTF-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if err != nil {
			return nil, failure("mime", Rejected, 0)
		}
		q := quotedprintable.NewWriter(p)
		if _, err = q.Write([]byte(part.body)); err != nil {
			return nil, failure("mime", Rejected, 0)
		}
		if err = q.Close(); err != nil {
			return nil, failure("mime", Rejected, 0)
		}
	}
	if err := w.Close(); err != nil {
		return nil, failure("mime", Rejected, 0)
	}
	return b.Bytes(), nil
}
