// Package emailnorm provides canonical email address normalization.
package emailnorm

import (
	"fmt"
	"net/mail"
	"strings"
)

// Normalize parses an email address and returns the lowercase addr-spec.
func Normalize(value string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	email := strings.ToLower(strings.TrimSpace(addr.Address))
	if email == "" || !strings.Contains(email, "@") {
		return "", fmt.Errorf("invalid email")
	}
	return email, nil
}
