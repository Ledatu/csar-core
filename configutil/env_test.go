package configutil

import (
	"os"
	"reflect"
	"testing"
)

func TestSafeExpandEnv_Basic(t *testing.T) {
	t.Setenv("TESTVAR", "hello")
	got := SafeExpandEnv("prefix-${TESTVAR}-suffix")
	want := "prefix-hello-suffix"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafeExpandEnv_PreservesBackRefs(t *testing.T) {
	got := SafeExpandEnv("/api/$1/items/$2")
	want := "/api/$1/items/$2"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafeExpandEnv_MixedBackRefsAndVars(t *testing.T) {
	t.Setenv("BASE", "/v2")
	got := SafeExpandEnv("$BASE/users/$1")
	want := "/v2/users/$1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafeExpandEnv_UnsetVar(t *testing.T) {
	os.Unsetenv("NOEXIST_VAR_XYZ")
	got := SafeExpandEnv("${NOEXIST_VAR_XYZ}")
	if got != "" {
		t.Errorf("got %q, want empty string for unset var", got)
	}
}

func TestExpandEnvInStruct(t *testing.T) {
	t.Setenv("HOST", "example.com")
	t.Setenv("PORT", "8080")

	type inner struct {
		Addr string
	}
	type cfg struct {
		Host   string
		Port   string
		Nested inner
		Tags   map[string]string
		Items  []string
	}

	c := cfg{
		Host:   "${HOST}",
		Port:   "$PORT",
		Nested: inner{Addr: "${HOST}:${PORT}"},
		Tags:   map[string]string{"url": "http://${HOST}"},
		Items:  []string{"$HOST", "literal"},
	}

	ExpandEnvInStruct(reflect.ValueOf(&c).Elem())

	if c.Host != "example.com" {
		t.Errorf("Host = %q", c.Host)
	}
	if c.Port != "8080" {
		t.Errorf("Port = %q", c.Port)
	}
	if c.Nested.Addr != "example.com:8080" {
		t.Errorf("Nested.Addr = %q", c.Nested.Addr)
	}
	if c.Tags["url"] != "http://example.com" {
		t.Errorf("Tags[url] = %q", c.Tags["url"])
	}
	if c.Items[0] != "example.com" {
		t.Errorf("Items[0] = %q", c.Items[0])
	}
	if c.Items[1] != "literal" {
		t.Errorf("Items[1] = %q", c.Items[1])
	}
}
