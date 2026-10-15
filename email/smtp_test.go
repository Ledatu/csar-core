package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar-core/secret"
)

type smtpScenario struct {
	mode            string
	noStartTLS      bool
	rejectRecipient int
	authCode        int
	finalCode       int
	disconnect      bool
	quitFailure     bool
	hang            bool
}

type smtpResult struct {
	body     []byte
	commands []string
	err      error
}

func smtpFixture(t *testing.T, scenario smtpScenario) (*smtpSender, <-chan smtpResult) {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	certs := certServer.TLS.Certificates
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	certServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	cfg := SMTPConfig{Host: "127.0.0.1", Port: portNumber, TLSMode: scenario.mode, Username: "test-user", Password: secret.NewSecret("test-password"), Timeout: configutil.Duration{Duration: time.Second}}
	sender := newSMTP(&cfg)
	sender.tlsConfig.RootCAs = pool
	result := make(chan smtpResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- smtpResult{err: acceptErr}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if scenario.hang {
			_, _ = io.Copy(io.Discard, conn)
			result <- smtpResult{}
			return
		}
		if scenario.mode == TLSImplicit {
			conn = tls.Server(conn, &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS12})
		}
		r := smtpResult{}
		p := textproto.NewConn(conn)
		write := func(format string, args ...any) bool {
			if r.err != nil {
				return false
			}
			r.err = p.PrintfLine(format, args...)
			return r.err == nil
		}
		read := func(prefix string) bool {
			line, readErr := p.ReadLine()
			if readErr != nil {
				r.err = readErr
				return false
			}
			r.commands = append(r.commands, line)
			if !strings.HasPrefix(line, prefix) {
				r.err = fmt.Errorf("unexpected test SMTP command for %s", prefix)
				return false
			}
			return true
		}
		defer func() { result <- r }()
		if !write("220 test") || !read("EHLO ") {
			return
		}
		if scenario.mode == TLSStartTLS {
			if scenario.noStartTLS {
				write("250 test")
				return
			}
			if !write("250-test\r\n250 STARTTLS") || !read("STARTTLS") || !write("220 begin TLS") {
				return
			}
			conn = tls.Server(conn, &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS12})
			p = textproto.NewConn(conn)
			if !read("EHLO ") {
				return
			}
		}
		if !write("250-test\r\n250 AUTH LOGIN") || !read("AUTH LOGIN") || !write("334 VXNlcm5hbWU6") {
			return
		}
		if !read(base64.StdEncoding.EncodeToString([]byte("test-user"))) || !write("334 UGFzc3dvcmQ6") {
			return
		}
		if !read(base64.StdEncoding.EncodeToString([]byte("test-password"))) || !write("%d authenticated", func() int {
			if scenario.authCode != 0 {
				return scenario.authCode
			}
			return 235
		}()) {
			return
		}
		if scenario.authCode != 0 {
			if !read("*") || !write("501 abort") || !read("QUIT") {
				return
			}
			write("221 bye")
			return
		}
		if !read("MAIL FROM:<sender@example.com>") || !write("250 sender") || !read("RCPT TO:<recipient@example.com>") {
			return
		}
		if scenario.rejectRecipient != 0 {
			write("%d secret-response test-password 123456", scenario.rejectRecipient)
			return
		}
		if !write("250 recipient") || !read("DATA") || !write("354 message") {
			return
		}
		r.body, r.err = io.ReadAll(p.DotReader())
		if r.err != nil || scenario.disconnect {
			return
		}
		code := scenario.finalCode
		if code == 0 {
			code = 250
		}
		if !write("%d secret-response 123456", code) || code != 250 {
			return
		}
		if !read("QUIT") {
			return
		}
		if !scenario.quitFailure {
			write("221 bye")
		}
	}()
	return sender, result
}

func exampleMessage() *Message {
	return &Message{From: `"Отправитель" <sender@example.com>`, To: "recipient@example.com", Subject: "Код входа", TextBody: "Ваш код: 123456\nВторая строка", HTMLBody: "<p>Ваш код: <b>123456</b></p>", ID: "<stable@example.com>"}
}

func TestSMTPSubmissionTLSAndMIME(t *testing.T) {
	for _, mode := range []string{TLSImplicit, TLSStartTLS} {
		t.Run(mode, func(t *testing.T) {
			sender, result := smtpFixture(t, smtpScenario{mode: mode, quitFailure: true})
			receipt, err := sender.Send(context.Background(), exampleMessage())
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Provider != ProviderSelectel || receipt.MessageID != "<stable@example.com>" {
				t.Fatalf("unexpected receipt: %+v", receipt)
			}
			r := <-result
			if r.err != nil {
				t.Fatal(r.err)
			}
			msg, err := mail.ReadMessage(bytes.NewReader(r.body))
			if err != nil {
				t.Fatal(err)
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			if err != nil || subject != exampleMessage().Subject {
				t.Fatalf("subject not preserved: %q, %v", subject, err)
			}
			if msg.Header.Get("Message-ID") != "<stable@example.com>" {
				t.Fatal("message ID lost")
			}
			_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			parts := multipart.NewReader(msg.Body, params["boundary"])
			for _, expected := range []string{exampleMessage().TextBody, exampleMessage().HTMLBody} {
				part, partErr := parts.NextRawPart()
				if partErr != nil {
					t.Fatal(partErr)
				}
				body, bodyErr := io.ReadAll(quotedprintable.NewReader(part))
				if bodyErr != nil || strings.ReplaceAll(string(body), "\r\n", "\n") != expected {
					t.Fatalf("body changed: %v", bodyErr)
				}
			}
		})
	}
}

func TestSMTPFailureOutcomesAndRedaction(t *testing.T) {
	for _, tt := range []struct {
		name     string
		scenario smtpScenario
		outcome  Outcome
		code     int
	}{
		{"auth rejection", smtpScenario{mode: TLSImplicit, authCode: 535}, Rejected, 535},
		{"temporary recipient", smtpScenario{mode: TLSImplicit, rejectRecipient: 450}, Retryable, 450},
		{"permanent recipient", smtpScenario{mode: TLSImplicit, rejectRecipient: 550}, Rejected, 550},
		{"temporary DATA", smtpScenario{mode: TLSImplicit, finalCode: 451}, Retryable, 451},
		{"permanent DATA", smtpScenario{mode: TLSImplicit, finalCode: 554}, Rejected, 554},
		{"lost DATA reply", smtpScenario{mode: TLSImplicit, disconnect: true}, Unknown, 0},
		{"missing STARTTLS", smtpScenario{mode: TLSStartTLS, noStartTLS: true}, Rejected, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sender, result := smtpFixture(t, tt.scenario)
			_, err := sender.Send(context.Background(), exampleMessage())
			var sendErr *SendError
			if !errors.As(err, &sendErr) || sendErr.Outcome != tt.outcome || sendErr.Code != tt.code {
				t.Fatalf("unexpected failure: %v", err)
			}
			if strings.Contains(err.Error(), "123456") || strings.Contains(err.Error(), "test-password") {
				t.Fatal("SMTP reply leaked")
			}
			if r := <-result; r.err != nil {
				t.Fatal(r.err)
			}
		})
	}
}

func TestSMTPCertificateVerification(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(strconv.FormatBool(mismatch), func(t *testing.T) {
			sender, result := smtpFixture(t, smtpScenario{mode: TLSImplicit})
			if mismatch {
				sender.tlsConfig.ServerName = "untrusted.invalid"
			} else {
				sender.tlsConfig.RootCAs = x509.NewCertPool()
			}
			if _, err := sender.Send(context.Background(), exampleMessage()); err == nil {
				t.Fatal("invalid certificate accepted")
			}
			if r := <-result; len(r.commands) != 0 {
				t.Fatal("sent credentials before verifying TLS")
			}
		})
	}
}

func TestSMTPCancellationAndTimeout(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelEarly), func(t *testing.T) {
			sender, result := smtpFixture(t, smtpScenario{mode: TLSImplicit, hang: true})
			sender.cfg.Timeout.Duration = 100 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelEarly {
				timer := time.AfterFunc(20*time.Millisecond, cancel)
				defer timer.Stop()
			}
			start := time.Now()
			if _, err := sender.Send(ctx, exampleMessage()); err == nil {
				t.Fatal("expected bounded send failure")
			}
			if time.Since(start) > time.Second {
				t.Fatal("SMTP operation did not honor cancellation/timeout")
			}
			<-result
		})
	}
}

func TestMessageValidationBeforeNetwork(t *testing.T) {
	for _, mutate := range []func(*Message){
		func(m *Message) { m.Subject = "code\r\nBcc: injected@example.com" },
		func(m *Message) { m.From = "sender@example.com\r\nBcc: injected@example.com" },
		func(m *Message) { m.To = "one@example.com, two@example.com" },
		func(m *Message) { m.ID = "<bad id@example.com>" },
	} {
		m := exampleMessage()
		mutate(m)
		sender := newSMTP(&SMTPConfig{})
		_, err := sender.Send(context.Background(), m)
		var sendErr *SendError
		if !errors.As(err, &sendErr) || sendErr.Outcome != Rejected {
			t.Fatalf("invalid message reached transport: %v", err)
		}
	}
}

func TestLoginAuthRefusesPlaintextAndExtraChallenges(t *testing.T) {
	a := &loginAuth{host: "smtp.example.com"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.example.com"}); err == nil {
		t.Fatal("plaintext authentication accepted")
	}
	for range 2 {
		if _, err := a.Next(nil, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Next(nil, true); err == nil {
		t.Fatal("unbounded LOGIN challenge accepted")
	}
}
