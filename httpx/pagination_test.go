package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePagination_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items", nil)
	p := ParsePagination(r, 20, 100)

	if p.Limit != 20 {
		t.Errorf("Limit = %d, want 20", p.Limit)
	}
	if p.Offset != 0 {
		t.Errorf("Offset = %d, want 0", p.Offset)
	}
}

func TestParsePagination_Custom(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?limit=50&offset=10", nil)
	p := ParsePagination(r, 20, 100)

	if p.Limit != 50 {
		t.Errorf("Limit = %d, want 50", p.Limit)
	}
	if p.Offset != 10 {
		t.Errorf("Offset = %d, want 10", p.Offset)
	}
}

func TestParsePagination_ClampsToMax(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?limit=500", nil)
	p := ParsePagination(r, 20, 100)

	if p.Limit != 100 {
		t.Errorf("Limit = %d, want 100 (clamped)", p.Limit)
	}
}

func TestParsePagination_InvalidValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?limit=abc&offset=-5", nil)
	p := ParsePagination(r, 20, 100)

	if p.Limit != 20 {
		t.Errorf("Limit = %d, want 20 (default on invalid)", p.Limit)
	}
	if p.Offset != 0 {
		t.Errorf("Offset = %d, want 0 (default on negative)", p.Offset)
	}
}

func TestPageResponse_JSON(t *testing.T) {
	resp := PageResponse[string]{
		Items:  []string{"a", "b"},
		Total:  10,
		Limit:  2,
		Offset: 0,
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["total"].(float64) != 10 {
		t.Errorf("total = %v, want 10", decoded["total"])
	}
	items := decoded["items"].([]any)
	if len(items) != 2 {
		t.Errorf("items count = %d, want 2", len(items))
	}
}
