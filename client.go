// Package secureaccess is a Cisco Secure Access REST client library for Go.
package secureaccess

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
)

const (
	DefaultMaxRetries          int     = 3
	DefaultMaxRateLimitRetries int     = 10
	DefaultBackoffMinDelay     int     = 2
	DefaultBackoffMaxDelay     int     = 60
	DefaultBackoffDelayFactor  float64 = 3
	DefaultMaxItems            int     = 100
	// DefaultRateLimit is the fixed client-side request rate, in requests per
	// second, applied to every outgoing HTTP request.
	DefaultRateLimit float64 = 5
)

// Client is an HTTP Secure Access client.
// Use secureaccess.NewClient to initiate a client.
// This will ensure proper cookie handling and processing of modifiers.
type Client struct {
	// HttpClient is the *http.Client used for API requests.
	HttpClient *http.Client
	// url is the Secure Access API gateway, eg. https://api.sse.cisco.com
	url string
	// key is the Secure Access API key
	key string
	// secret is the Secure Access API secret
	secret string
	// orgID is the Multi-org and Managed Child Organizations ID
	orgID string
	// accessToken is the current access token
	accessToken string
	// userAgent is the HTTP User-Agent string
	userAgent string

	// Maximum number of retries
	maxRetries int
	// Maximum number of retries after an HTTP 429. Kept separate from
	// maxRetries because a 429 means the request was early, not that it
	// failed, and it should not consume the budget reserved for real errors.
	maxRateLimitRetries int
	// Minimum delay between two retries
	backoffMinDelay int
	// Maximum delay between two retries
	backoffMaxDelay int
	// Backoff delay factor
	backoffDelayFactor float64
	// expirationTime is the timestamp of the authentication token expiration
	expirationTime time.Time

	// Authentication mutex
	authenticationMutex *sync.RWMutex
	// Maximum number of items retrieved in a single GET request
	maxItems int
	// configErrs collects validation errors raised by modifiers.
	configErrs []error

	// make sure that either readers or writers are active at a time.
	readers chan int
	writers chan int

	// limiter paces outgoing HTTP requests at DefaultRateLimit requests per
	// second. It is shared by all goroutines using this client, and applies to
	// authentication and to every retry attempt as well.
	limiter *rate.Limiter
}

// NewClient creates a new Secure Access HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("https://api.sse.cisco.com", "key", "secret", RequestTimeout(120*time.Second), MaxRetries(5))
func NewClient(url, key, secret string, mods ...func(*Client)) (Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		Proxy:           http.ProxyFromEnvironment,
	}

	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
		Jar:       cookieJar,
	}

	client := Client{
		HttpClient:          &httpClient,
		url:                 url,
		userAgent:           "go-secureaccess netascode",
		key:                 key,
		secret:              secret,
		maxRetries:          DefaultMaxRetries,
		maxRateLimitRetries: DefaultMaxRateLimitRetries,
		backoffMinDelay:     DefaultBackoffMinDelay,
		backoffMaxDelay:     DefaultBackoffMaxDelay,
		backoffDelayFactor:  DefaultBackoffDelayFactor,
		maxItems:            DefaultMaxItems,
		authenticationMutex: &sync.RWMutex{},
		readers:             make(chan int),
		writers:             make(chan int),
		limiter:             rate.NewLimiter(rate.Limit(DefaultRateLimit), 1),
	}
	go runModeGate(client.readers, client.writers)

	for _, mod := range mods {
		mod(&client)
	}

	// Cross-field validation.
	if client.backoffMinDelay > client.backoffMaxDelay {
		client.configErrs = append(client.configErrs, fmt.Errorf(
			"BackoffMinDelay (%d) must not be greater than BackoffMaxDelay (%d)",
			client.backoffMinDelay, client.backoffMaxDelay))
	}

	if len(client.configErrs) > 0 {
		errs := errors.Join(client.configErrs...)
		client.configErrs = nil
		return client, fmt.Errorf("invalid client configuration: %w", errs)
	}

	return client, nil
}

// Replace the default HTTP client with a custom one.
func CustomHttpClient(httpClient *http.Client) func(*Client) {
	return func(client *Client) {
		client.HttpClient = httpClient
	}
}

// UserAgent modifies the HTTP user agent string. Default value is 'go-secureaccess netascode'.
func UserAgent(x string) func(*Client) {
	return func(client *Client) {
		client.userAgent = x
	}
}

// OrgId modifies the organization ID.
func OrgId(x string) func(*Client) {
	return func(client *Client) {
		client.orgID = x
	}
}

// Insecure determines if insecure https connections are allowed. Default value is false.
func Insecure(x bool) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = x
	}
}

// RequestTimeout modifies the HTTP request timeout from the default of 60 seconds.
func RequestTimeout(x time.Duration) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Timeout = x
	}
}

// MaxRetries modifies the maximum number of retries from the default of 3.
// A value of 0 disables retries.
func MaxRetries(x int) func(*Client) {
	return func(client *Client) {
		if x < 0 {
			client.configErrs = append(client.configErrs,
				fmt.Errorf("MaxRetries must be >= 0, got %d", x))
			return
		}
		client.maxRetries = x
	}
}

// BackoffMinDelay modifies the minimum delay between two retries, in seconds,
// from the default of 2. A value of 0 retries without delay.
func BackoffMinDelay(x int) func(*Client) {
	return func(client *Client) {
		if x < 0 {
			client.configErrs = append(client.configErrs,
				fmt.Errorf("BackoffMinDelay must be >= 0 seconds, got %d", x))
			return
		}
		client.backoffMinDelay = x
	}
}

// BackoffMaxDelay modifies the maximum delay between two retries, in seconds,
// from the default of 60. It must not be smaller than BackoffMinDelay.
func BackoffMaxDelay(x int) func(*Client) {
	return func(client *Client) {
		if x < 0 {
			client.configErrs = append(client.configErrs,
				fmt.Errorf("BackoffMaxDelay must be >= 0 seconds, got %d", x))
			return
		}
		client.backoffMaxDelay = x
	}
}

// BackoffDelayFactor modifies the backoff delay factor from the default of 3.
// It must be >= 1: a smaller factor would make each successive retry wait less
// than the one before it.
func BackoffDelayFactor(x float64) func(*Client) {
	return func(client *Client) {
		if x < 1 {
			client.configErrs = append(client.configErrs,
				fmt.Errorf("BackoffDelayFactor must be a finite number >= 1, got %v", x))
			return
		}
		client.backoffDelayFactor = x
	}
}

// MaxItems modifies the maximum number of items retrieved in a single GET request
// from the default of 100. It must be > 0.
func MaxItems(x int) func(*Client) {
	return func(client *Client) {
		if x <= 0 {
			client.configErrs = append(client.configErrs,
				fmt.Errorf("MaxItems must be > 0, got %d", x))
			return
		}
		client.maxItems = x
	}
}

// MaxRateLimitRetries modifies the maximum number of retries after an HTTP 429
// from the default of 10. A value of 0 disables retrying on 429.
func MaxRateLimitRetries(x int) func(*Client) {
	return func(client *Client) {
		if x < 0 {
			client.configErrs = append(client.configErrs, fmt.Errorf(
				"MaxRateLimitRetries must not be negative, got %d", x))
			return
		}
		client.maxRateLimitRetries = x
	}
}

// NewReq creates a new Req request for this client.
//
// The context governs the entire lifetime of the request once it is passed to
// Do: connection setup, rate limiting, retries and backoff, and reading the
// response body. Do takes its context from the request, so ctx must outlive the
// Do call.
func (client *Client) NewReq(ctx context.Context, method, uri string, body io.Reader, mods ...func(*Req)) (Req, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, client.url+uri, body)
	if err != nil {
		return Req{}, fmt.Errorf("failed to create %s request: %w", method, err)
	}
	req := Req{
		HttpReq:    httpReq,
		LogPayload: true,
	}

	for _, mod := range mods {
		mod(&req)
	}

	if req.RequestID == "" {
		req.RequestID = generateRequestID(8)
	}

	return req, nil
}

// Do makes a request.
// Requests for Do are built outside of the client, e.g.
//
//	req, err := client.NewReq(ctx, "GET", "/policies/v2/rules", nil)
//	res, err := client.Do(req)
//
// Like http.Client.Do, the context comes from the request rather than from a
// separate parameter, so there is only ever one context in play.
func (client *Client) Do(req Req) (Res, error) {
	if req.HttpReq == nil {
		return Res{}, fmt.Errorf("invalid request: HttpReq is nil, use Client.NewReq to build a request")
	}

	ctx := req.HttpReq.Context()

	err := client.Authenticate(ctx, "")
	if err != nil {
		return Res{}, err
	}

	// Save current auth token. In case of 401, we can check if the token has changed in the meantime
	accessToken := client.AccessToken()
	req.HttpReq.Header.Set("Authorization", "Bearer "+accessToken)
	req.HttpReq.Header.Add("Content-Type", "application/json")
	req.HttpReq.Header.Add("Accept", "application/json")
	req.HttpReq.Header.Add("User-Agent", client.userAgent)

	// retain the request body across multiple attempts
	var body []byte
	if req.HttpReq.Body != nil {
		body, _ = io.ReadAll(req.HttpReq.Body)
	}

	var res Res

	if req.HttpReq.Method == "DELETE" || req.HttpReq.Method == "POST" || req.HttpReq.Method == "PUT" {
		client.writers <- +1
		defer func() { client.writers <- -1 }()
	}

	for attempts := 0; ; attempts++ {
		httpRes, err := client.do(ctx, req, body)
		if err != nil {
			if ok := client.Backoff(ctx, attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection error occurred: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection failed: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}

		bodyBytes, err := io.ReadAll(httpRes.Body)
		httpRes.Body.Close()
		if err != nil {
			if ok := client.Backoff(ctx, attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}
		res = gjson.ParseBytes(bodyBytes)
		log.Printf("[DEBUG] [ReqID: %s] HTTP Response Headers (StatusCode %d): %s", req.RequestID, httpRes.StatusCode, formatHeaders(httpRes.Header))
		if req.LogPayload {
			log.Printf("[DEBUG] [ReqID: %s] HTTP Response (StatusCode %d): %s", req.RequestID, httpRes.StatusCode, res.Raw)
		}

		if httpRes.StatusCode >= 200 && httpRes.StatusCode <= 299 {
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			break
		} else {
			if ok := client.Backoff(ctx, attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
			} else if httpRes.StatusCode >= 500 && httpRes.StatusCode <= 599 {
				log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v, Retries: %v", req.RequestID, httpRes.StatusCode, attempts)
				continue
			} else if httpRes.StatusCode == 401 {
				// When request fails with 401, this indicates invalid authentication tokens
				log.Printf("[DEBUG] [ReqID: %s] Invalid session detected. Reauthenticating...", req.RequestID)
				err := client.Authenticate(ctx, accessToken)
				if err != nil {
					log.Printf("[DEBUG] [ReqID: %s] HTTP Request failed: StatusCode 401: Reauthentication failed with StatusCode (%d): %s", req.RequestID, httpRes.StatusCode, err.Error())
					return res, fmt.Errorf("HTTP Request failed: StatusCode 401: Reauthentication failed with StatusCode (%d): %s", httpRes.StatusCode, err.Error())
				}
				// Save authentication token in case next 401 is received
				accessToken = client.AccessToken()
				req.HttpReq.Header.Set("Authorization", "Bearer "+accessToken)
				continue
			}
			// In case any previous conditions don't `continue`, return error
			log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
		}
	}

	return res, nil
}

func (client *Client) do(ctx context.Context, req Req, body []byte) (*http.Response, error) {
	if err := client.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req.HttpReq.Body = io.NopCloser(bytes.NewReader(body))
	if req.LogPayload {
		log.Printf("[DEBUG] [ReqID: %s] HTTP Request: %s, %s, %s", req.RequestID, req.HttpReq.Method, req.HttpReq.URL, string(body))
	} else {
		log.Printf("[DEBUG] [ReqID: %s] HTTP Request: %s, %s", req.RequestID, req.HttpReq.Method, req.HttpReq.URL)
	}
	log.Printf("[DEBUG] [ReqID: %s] HTTP Request Headers: %s", req.RequestID, formatHeaders(req.HttpReq.Header))

	return client.HttpClient.Do(req.HttpReq)
}

// Get makes a GET requests and returns a GJSON result.
// It handles pagination and returns all items in a single response.
func (client *Client) Get(ctx context.Context, path string, mods ...func(*Req)) (Res, error) {
	client.readers <- 1
	defer func() { client.readers <- -1 }()

	// Check if path contains 'limit' or 'offset' query parameters.
	// If so, assume user is doing a paginated request and return the raw data.
	if hasQueryParam(path, "limit") || hasQueryParam(path, "offset") {
		return client.get(ctx, path, mods...)
	}

	// Execute query as provided by user
	raw, err := client.get(ctx, path, mods...)
	if err != nil {
		return raw, err
	}

	count := raw.Get("count")
	limit := raw.Get("limit")

	// Pagination data not available, return the raw data as is
	if !count.Exists() || !limit.Exists() {
		return raw, nil
	}

	// All items are already returned in a single response, return the raw data as is
	if count.Int() <= limit.Int() {
		return raw, nil
	}

	log.Printf("[DEBUG] Paginated response detected")

	// Generate Request ID for tracking all get requests under a single ID
	reqID := generateRequestID(8)
	mods = append(mods, RequestID(reqID))

	// Build the merged response in a single pass
	var sb strings.Builder
	sb.WriteString(`{"results":[`)
	first := true
	offset := 0
	for {
		// Get URL path with offset and limit set
		urlPath := pathWithOffset(path, offset, client.maxItems)

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}

		// Check if there are any items in the response.
		results := raw.Get("results")
		if !results.IsArray() {
			if results.Exists() {
				log.Printf("[DEBUG] [ReqID: %s] Ignoring non-array 'results' field (type %s) at offset %d", reqID, results.Type, offset)
			}
			break
		}

		// Strip surrounding square brackets and append items directly.
		if chunk := strings.TrimSpace(results.Raw[1 : len(results.Raw)-1]); chunk != "" {
			if !first {
				sb.WriteByte(',')
			}
			sb.WriteString(chunk)
			first = false
		}

		// If there are no more pages, stop reading
		if count.Int() <= int64(offset+client.maxItems) {
			break
		}

		// Increase offset to get next bulk of data
		offset += client.maxItems
	}

	sb.WriteString(`]}`)
	return gjson.Parse(sb.String()), nil
}

// get makes a GET request and returns a GJSON result.
// It does the exact request it is told to do.
// Results will be the raw data structure as returned by the API.
func (client *Client) get(ctx context.Context, path string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "GET", path, nil, mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Delete makes a DELETE request.
func (client *Client) Delete(ctx context.Context, path string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "DELETE", path, nil, mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Delete makes a DELETE request.
func (client *Client) DeleteWithBody(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "DELETE", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Post makes a POST request and returns a GJSON result.
// Hint: Use the Body struct to easily create POST body data.
func (client *Client) Post(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "POST", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Put makes a PUT request and returns a GJSON result.
// Hint: Use the Body struct to easily create PUT body data.
func (client *Client) Put(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "PUT", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Patch makes a PATCH request and returns a GJSON result.
// Hint: Use the Body struct to easily create PATCH body data.
func (client *Client) Patch(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "PATCH", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// AccessToken returns the current token
func (client *Client) AccessToken() string {
	client.authenticationMutex.RLock()
	defer client.authenticationMutex.RUnlock()

	return client.accessToken
}

// Authenticate assures the token is there and is valid.
// currentAccessToken is the token used in the request. This helps to
// determine, if accessToken needs refreshing or has already been refreshed by other thread.
// currentAccessToken can be an empty string.
func (client *Client) Authenticate(ctx context.Context, currentAccessToken string) error {
	client.authenticationMutex.Lock()
	defer client.authenticationMutex.Unlock()

	if client.accessToken != "" && currentAccessToken == "" {
		// accessToken is present, no error reported, do nothing
		return nil
	}

	if currentAccessToken != "" && currentAccessToken != client.accessToken {
		// accessToken has changed since the last request
		// we assume some other thread has already refreshed it, do nothing
		return nil
	}

	// No accessToken - login
	for attempts := 0; ; attempts++ {
		req, err := client.NewReq(ctx, "POST", "/auth/v2/token", strings.NewReader(""), NoLogPayload)
		if err != nil {
			// A malformed request is deterministic, retrying cannot help.
			log.Printf("[ERROR] Authentication failed: %v", err)
			return err
		}
		req.HttpReq.Header.Add("User-Agent", client.userAgent)
		req.HttpReq.SetBasicAuth(client.key, client.secret)
		if client.orgID != "" {
			req.HttpReq.Header.Add("X-Umbrella-OrgId", client.orgID)
		}

		if err := client.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter: %w", err)
		}

		httpRes, err := client.HttpClient.Do(req.HttpReq)
		if err != nil {
			return err
		}
		bodyBytes, _ := io.ReadAll(httpRes.Body)
		httpRes.Body.Close()

		if httpRes.StatusCode == 200 {
			bodyJson := gjson.ParseBytes(bodyBytes)
			client.accessToken = bodyJson.Get("access_token").String()
			client.expirationTime = time.Now().Add(time.Duration(bodyJson.Get("expires_in").Int()) * time.Second)
			log.Printf("[DEBUG] Authentication successful")
			return nil
		}

		// Only rate limiting (429) and server-side errors (5xx) are worth retrying.
		if isRetryableStatus(httpRes.StatusCode) && client.Backoff(ctx, attempts) {
			log.Printf("[ERROR] Authentication failed: StatusCode %v, retries: %v, response body: %s", httpRes.StatusCode, attempts, string(bodyBytes))
			continue
		}

		client.accessToken = ""
		if attempts == 0 {
			log.Printf("[ERROR] Authentication failed: StatusCode %v, response body: %s", httpRes.StatusCode, string(bodyBytes))
			return fmt.Errorf("authentication failed, status code: %v, response body: %s", httpRes.StatusCode, string(bodyBytes))
		}
		log.Printf("[ERROR] Authentication failed after %v retries: StatusCode %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
		return fmt.Errorf("authentication failed after %v retries, status code: %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
	}
}

// Backoff waits following an exponential backoff algorithm.
// It reports whether the caller should retry: false means the retry budget is
// exhausted, or ctx was cancelled before or during the wait.
func (client *Client) Backoff(ctx context.Context, attempts int) bool {
	log.Printf("[DEBUG] Beginning backoff method: attempt %v of %v", attempts, client.maxRetries)
	if attempts >= client.maxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	// Do not start a wait that is already pointless.
	if err := ctx.Err(); err != nil {
		log.Printf("[DEBUG] Exit from backoff method with return value false: %v", err)
		return false
	}

	minDelay := time.Duration(client.backoffMinDelay) * time.Second
	maxDelay := time.Duration(client.backoffMaxDelay) * time.Second

	min := float64(minDelay)
	backoff := min * math.Pow(client.backoffDelayFactor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))

	timer := time.NewTimer(backoffDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		log.Printf("[DEBUG] Exit from backoff method with return value true")
		return true
	case <-ctx.Done():
		log.Printf("[DEBUG] Exit from backoff method with return value false: %v", ctx.Err())
		return false
	}
}
