package secureaccess

import (
	"github.com/tidwall/gjson"
)

// Res is an API response returned by client requests.
// This is a GJSON result, which offers advanced and safe parsing capabilities.
// https://github.com/tidwall/gjson
type Res struct {
	gjson.Result

	// StatusCode is the HTTP status code of the response, or 0 if no
	// response was received.
	StatusCode int

	// RequestID is the unique identifier of the request this response
	// belongs to.
	RequestID string
}
