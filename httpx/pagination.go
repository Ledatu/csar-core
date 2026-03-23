package httpx

import (
	"net/http"
	"strconv"
)

// Pagination holds parsed limit/offset query parameters.
type Pagination struct {
	Limit  int
	Offset int
}

// ParsePagination extracts limit and offset from query parameters.
// Values are clamped to [1, maxLimit] for limit and >= 0 for offset.
func ParsePagination(r *http.Request, defaultLimit, maxLimit int) Pagination {
	p := Pagination{Limit: defaultLimit}

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.Limit = n
		}
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.Offset = n
		}
	}

	return p
}

// PageResponse is a generic paginated API response envelope.
type PageResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
