package email

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type smtpSender struct {
	cfg       SMTPConfig
	tlsConfig *tls.Config
}

func newSMTP(cfg *SMTPConfig) *smtpSender {
	return &smtpSender{cfg: *cfg, tlsConfig: &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}}
}

func (s *smtpSender) Send(ctx context.Context, msg *Message) (Receipt, error) {
	m, from, to, err := prepare(msg)
	if err != nil {
		return Receipt{}, err
	}
	if !ascii(from.Address) || !ascii(to.Address) {
		return Receipt{}, failure("smtp_address", Rejected, 0)
	}
	body, err := mimeMessage(&m)
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout.Duration)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return Receipt{}, smtpFailure("connect", err, false)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return Receipt{}, smtpFailure("deadline", err, false)
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if s.cfg.TLSMode == TLSImplicit {
		tlsConn := tls.Client(conn, s.tlsConfig.Clone())
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return Receipt{}, smtpFailure("tls", err, false)
		}
		conn = tlsConn
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return Receipt{}, smtpFailure("greeting", err, false)
	}
	defer func() { _ = c.Close() }()
	if s.cfg.TLSMode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return Receipt{}, failure("starttls_required", Rejected, 0)
		}
		if err = c.StartTLS(s.tlsConfig.Clone()); err != nil {
			return Receipt{}, smtpFailure("starttls", err, false)
		}
	}
	if ok, methods := c.Extension("AUTH"); !ok || !hasLOGIN(methods) {
		return Receipt{}, failure("auth_login_required", Rejected, 0)
	}
	if err = c.Auth(&loginAuth{username: s.cfg.Username, password: s.cfg.Password.Plaintext(), host: s.cfg.Host}); err != nil {
		return Receipt{}, smtpFailure("auth", err, false)
	}
	if err = c.Mail(from.Address); err != nil {
		return Receipt{}, smtpFailure("mail", err, false)
	}
	if err = c.Rcpt(to.Address); err != nil {
		return Receipt{}, smtpFailure("recipient", err, false)
	}
	w, err := c.Data()
	if err != nil {
		return Receipt{}, smtpFailure("data", err, false)
	}
	if _, err = w.Write(body); err != nil {
		return Receipt{}, smtpFailure("body", err, true)
	}
	if err = w.Close(); err != nil {
		return Receipt{}, smtpFailure("acceptance", err, true)
	}
	// The final DATA reply already accepted the message. QUIT cannot revoke it;
	// treating a failed QUIT as a send error would cause duplicate retries.
	quitDeadline := time.Now().Add(time.Second)
	if deadline.Before(quitDeadline) {
		quitDeadline = deadline
	}
	_ = conn.SetDeadline(quitDeadline)
	_ = c.Quit()
	return Receipt{Provider: ProviderSelectel, MessageID: m.ID}, nil
}

func hasLOGIN(methods string) bool {
	for _, method := range strings.Fields(methods) {
		if strings.EqualFold(method, "LOGIN") {
			return true
		}
	}
	return false
}

func smtpFailure(stage string, err error, mayHaveAccepted bool) *SendError {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		outcome := Rejected
		if reply.Code >= 400 && reply.Code < 500 {
			outcome = Retryable
		}
		return failure(stage, outcome, reply.Code)
	}
	if mayHaveAccepted {
		return failure(stage, Unknown, 0)
	}
	return failure(stage, Retryable, 0)
}

// Selectel's documented SMTP setup uses AUTH LOGIN. Credentials are exchanged
// only after verified TLS; the bounded challenge sequence never logs replies.
type loginAuth struct {
	username, password, host string
	step                     int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS || server.Name != a.host {
		return "", nil, errors.New("SMTP authentication requires verified TLS")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	default:
		return nil, errors.New("unexpected SMTP authentication challenge")
	}
}
