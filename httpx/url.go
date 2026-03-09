package httpx

import "net/url"

// AppendQuery appends key-value pairs as query parameters to a base URL.
// Keys and values are provided as alternating strings. If the number of
// arguments is odd, the last key is silently ignored.
func AppendQuery(base string, kvs ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for i := 0; i+1 < len(kvs); i += 2 {
		q.Set(kvs[i], kvs[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}
