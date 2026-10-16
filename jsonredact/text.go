package jsonredact

import (
	"regexp"
	"strings"
)

var (
	cookieText     = regexp.MustCompile(`(?im)\b(set-cookie|cookie)\s*:\s*[^\r\n]+`)
	urlCredentials = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+:[^\s/@]+@`)
	credentialText = regexp.MustCompile(`(?i)\b(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret|token)["']?\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`)
	bearerText     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+`)
	jwtText        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`)
	emailText      = regexp.MustCompile(`[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+`)
)

// RedactText removes common credential representations from diagnostic text.
// Known credential values supplement patterns; callers must still restrict
// which fields and media types are eligible for persistence.
func RedactText(value string, secrets ...string) string {
	for _, secret := range secrets {
		if len(secret) >= 8 {
			value = strings.ReplaceAll(value, secret, DefaultMask)
		}
	}
	value = cookieText.ReplaceAllString(value, "$1: [REDACTED]")
	value = urlCredentials.ReplaceAllString(value, "${1}[REDACTED]@")
	value = bearerText.ReplaceAllString(value, "$1 [REDACTED]")
	value = credentialText.ReplaceAllString(value, "$1=[REDACTED]")
	value = jwtText.ReplaceAllString(value, DefaultMask)
	return emailText.ReplaceAllString(value, DefaultMask)
}
