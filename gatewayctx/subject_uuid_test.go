package gatewayctx

import (
	"testing"

	"github.com/google/uuid"
)

func TestSubjectUUID_Valid(t *testing.T) {
	want := uuid.New()
	id := Identity{Subject: want.String()}

	got, err := id.SubjectUUID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestSubjectUUID_Empty(t *testing.T) {
	id := Identity{}
	_, err := id.SubjectUUID()
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
}

func TestSubjectUUID_Invalid(t *testing.T) {
	id := Identity{Subject: "not-a-uuid"}
	_, err := id.SubjectUUID()
	if err == nil {
		t.Fatal("expected error for invalid uuid")
	}
}
