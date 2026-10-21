package secureaccess

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
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

// generateRequestID generates a random string of the specified length.
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
func pathWithOffset(path string, offset, limit int) (string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return path, err
	}

	q := u.Query()
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// pathWithPage returns path with the page and limit query parameters set,
// replacing them if they are already present.
func pathWithPage(path string, page, limit int) (string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return path, err
	}

	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// retryAfter parses the Retry-After header, given either as delay-seconds or as
// an HTTP-date. It reports false if the header is missing or malformed.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0, false
	}
	return max(time.Until(t), 0), true
}

// jitter adds a random 0-20% (at least up to 1s) on top of d, so clients that
// received the same Retry-After do not retry in lockstep. It never shortens d.
func jitter(d time.Duration) time.Duration {
	spread := max(d/5, time.Second)
	return d + rand.N(spread)
}

// sleepCtx waits for d, returning false early if ctx is done first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
