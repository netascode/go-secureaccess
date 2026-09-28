package secureaccess

import (
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// sensitiveHeaders are never logged in full; their values are replaced with a
// redaction marker.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

// formatHeaders renders HTTP headers as a single-line, log-friendly string with
// keys sorted for stable output. Values of sensitive headers are redacted, and
// multi-value headers are joined with ", ".
func formatHeaders(h http.Header) string {
	if len(h) == 0 {
		return "(none)"
	}

	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if sensitiveHeaders[strings.ToLower(k)] {
			parts = append(parts, k+": [REDACTED]")
			continue
		}
		parts = append(parts, k+": "+strings.Join(h[k], ", "))
	}

	return strings.Join(parts, " | ")
}

// generate random string
func generateRequestID(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

// checks if the HTTP status code is retryable
func isRetryableStatus(code int) bool {
	return code == 429 || (code >= 500 && code <= 599)
}

// pathWithOffset returns path with the offset and limit query parameters set,
// replacing them if they are already present.
func pathWithOffset(path string, offset, limit int) string {
	u, err := url.Parse(path)
	if err != nil {
		return path
	}

	q := u.Query()
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	return u.String()
}

// hasQueryParam reports whether path carries the named query parameter.
func hasQueryParam(path, param string) bool {
	u, err := url.Parse(path)
	if err != nil {
		return false
	}

	_, ok := u.Query()[param]
	return ok
}
