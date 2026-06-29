package emailnorm

import "testing"

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "bare mixed case",
			value: "User@Example.COM",
			want:  "user@example.com",
		},
		{
			name:  "display name",
			value: "User Name <User@Example.COM>",
			want:  "user@example.com",
		},
		{
			name:  "trim whitespace",
			value: "  User@Example.COM  ",
			want:  "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Normalize(tt.value)
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Normalize() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeRejectsInvalidEmail(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"not-an-email",
		"User Name <not-an-email>",
	}

	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			if got, err := Normalize(value); err == nil {
				t.Fatalf("Normalize() = %q, want error", got)
			}
		})
	}
}
