package secureaccess

import (
	"net/http"
)

// Req wraps http.Request for API requests.
type Req struct {
	// HttpReq is the *http.Request obejct.
	HttpReq *http.Request
	// LogPayload indicates whether logging of payloads should be enabled.
	LogPayload bool
	// ID for the request.
	RequestID string
}

// NoLogPayload prevents logging of payloads.
func NoLogPayload(req *Req) {
	req.LogPayload = false
}

// Set request ID
func RequestID(x string) func(*Req) {
	return func(req *Req) {
		req.RequestID = x
	}
}
