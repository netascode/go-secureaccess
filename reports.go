package secureaccess

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
)

// reportsPrefixes are the Reports API path prefixes, in the order they are
// tried. The Reports API is served under a region specific prefix, and the
// first one that answers successfully is used for all /reports requests.
var reportsPrefixes = []string{"/reports", "/reports.us", "/reports.eu"}

// reportsPrefix is the Reports API prefix discovered for this client.
type reportsPrefix struct {
	// mu serializes discovery, so concurrent requests do not probe in parallel.
	mu sync.Mutex
	// prefix is the discovered prefix, empty until a request succeeds.
	prefix string
}

// isReportsPath reports whether path belongs to the Reports API.
func isReportsPath(path string) bool {
	return path == "/reports" || strings.HasPrefix(path, "/reports/")
}

// setReportsPrefix replaces the leading /reports of path and rawPath with
// prefix and sets the result as the request path.
func setReportsPrefix(req Req, path, rawPath, prefix string) {
	req.HttpReq.URL.Path = prefix + strings.TrimPrefix(path, "/reports")
	if rawPath != "" {
		req.HttpReq.URL.RawPath = prefix + strings.TrimPrefix(rawPath, "/reports")
	}
}

// doReports makes a Reports API request. Until a prefix is known, the request
// is tried with each of reportsPrefixes in order, moving to the next prefix
// only on 403 Forbidden, which the API returns for a prefix outside the
// organization's region. The first prefix that succeeds is saved for all later
// /reports requests. Any other error is returned right away, and nothing is
// saved until a request succeeds.
func (client *Client) doReports(ctx context.Context, req Req, body []byte) (Res, error) {
	path, rawPath := req.HttpReq.URL.Path, req.HttpReq.URL.RawPath

	client.reports.mu.Lock()
	prefix := client.reports.prefix
	if prefix != "" {
		client.reports.mu.Unlock()
		setReportsPrefix(req, path, rawPath, prefix)
		res, _, err := client.doWithRetries(ctx, req, body)
		return res, err
	}
	defer client.reports.mu.Unlock()

	var res Res
	var err error
	for _, prefix := range reportsPrefixes {
		setReportsPrefix(req, path, rawPath, prefix)
		log.Printf("[DEBUG] [ReqID: %s] Trying Reports API prefix %s", req.RequestID, prefix)
		var statusCode int
		res, statusCode, err = client.doWithRetries(ctx, req, body)
		if err == nil {
			log.Printf("[DEBUG] [ReqID: %s] Using Reports API prefix %s", req.RequestID, prefix)
			client.reports.prefix = prefix
			return res, nil
		}
		if statusCode != http.StatusForbidden {
			return res, err
		}
	}
	return res, err
}
