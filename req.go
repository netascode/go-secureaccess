package secureaccess

import (
	"net/http"
)

// Req wraps http.Request for API requests.
type Req struct {
	// HttpReq is the *http.Request object.
	HttpReq *http.Request
	// LogPayload indicates whether logging of payloads should be enabled.
	LogPayload bool
	// RequestID carries the unique identifier for the request.
	RequestID string
}

// NoLogPayload prevents logging of payloads.
func NoLogPayload(req *Req) {
	req.LogPayload = false
}

// RequestID sets the unique identifier for the request.
func RequestID(x string) func(*Req) {
	return func(req *Req) {
		req.RequestID = x
	}
}
