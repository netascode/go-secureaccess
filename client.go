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
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
)

const (
	DefaultMaxRetries           int     = 3
	DefaultBackoffMinDelay      int     = 2
	DefaultBackoffMaxDelay      int     = 60
	DefaultBackoffDelayFactor   float64 = 3
	DefaultMaxAPICallsPerSecond int     = 5
	// MaxRetryAfterDelay is the longest Retry-After the client waits for.
	MaxRetryAfterDelay time.Duration = 5 * time.Minute
)

// Client is an HTTP Secure Access client.
// Use secureaccess.NewClient to initiate a client. A Client is safe for
// concurrent use and must not be copied: share the *Client returned by
// NewClient instead.
type Client struct {
	// HttpClient is the *http.Client used for API requests.
	HttpClient *http.Client
	// url is the Secure Access API gateway, eg. https://api.sse.cisco.com
	url string
	// key is the Secure Access API key
	key string
	// secret is the Secure Access API secret
	secret string
	// accessToken is the current access token
	accessToken string
	// userAgent is the HTTP User-Agent string
	UserAgent string

	// MaxRetries is the maximum number of retries
	MaxRetries int
	// BackoffMinDelay is the minimum delay between two retries (in seconds)
	BackoffMinDelay int
	// BackoffMaxDelay is the maximum delay between two retries (in seconds)
	BackoffMaxDelay int
	// BackoffDelayFactor is the backoff delay factor (multiplier for exponential backoff)
	BackoffDelayFactor float64

	// authenticationMutex makes sure that authentication-related operations are properly synchronized.
	authenticationMutex sync.RWMutex
	// expirationTime is the timestamp of the authentication token expiration
	// Token expiration time is one hour by default. Not tracking this explicitly.
	// Refresh will happen after failed request
	// expirationTime time.Time

	// configErrs collects validation errors raised by modifiers.
	configErrs []error

	// gate makes sure that either readers or writers are active at a time.
	gate *modeGate

	// limiter paces all outgoing API requests except for Authentication requests.
	limiter *rate.Limiter

	// reports holds the Reports API prefix discovered by the first successful
	// /reports request.
	reports *reportsPrefix
}

// NewClient creates a new Secure Access HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("https://api.sse.cisco.com", "key", "secret", RequestTimeout(120*time.Second), MaxRetries(5))
func NewClient(url, key, secret string, mods ...func(*Client)) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: false}
	tr.Proxy = http.ProxyFromEnvironment

	httpClient := http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
	}

	client := &Client{
		HttpClient:         &httpClient,
		url:                strings.TrimRight(url, "/"),
		UserAgent:          "go-secureaccess netascode",
		key:                key,
		secret:             secret,
		MaxRetries:         DefaultMaxRetries,
		BackoffMinDelay:    DefaultBackoffMinDelay,
		BackoffMaxDelay:    DefaultBackoffMaxDelay,
		BackoffDelayFactor: DefaultBackoffDelayFactor,
		limiter:            rate.NewLimiter(rate.Limit(DefaultMaxAPICallsPerSecond), 1),
		gate:               newModeGate(),
		reports:            &reportsPrefix{},
	}

	// Apply all modifiers to the client before performing cross-field validation.
	for _, mod := range mods {
		mod(client)
	}

	// Cross-field validation.
	if client.BackoffMinDelay > client.BackoffMaxDelay {
		client.configErrs = append(client.configErrs, fmt.Errorf(
			"BackoffMinDelay (%d) must not be greater than BackoffMaxDelay (%d)",
			client.BackoffMinDelay, client.BackoffMaxDelay))
	}

	if len(client.configErrs) > 0 {
		errs := errors.Join(client.configErrs...)
		client.configErrs = nil
		return nil, fmt.Errorf("invalid client configuration: %w", errs)
	}

	return client, nil
}

// Replace the default HTTP client with a custom one.
func CustomHttpClient(httpClient *http.Client) func(*Client) {
	return func(client *Client) {
		client.HttpClient = httpClient
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

// UserAgent modifies the HTTP user agent string. Default value is 'go-secureaccess netascode'.
func UserAgent(x string) func(*Client) {
	return func(client *Client) {
		client.UserAgent = x
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
		client.MaxRetries = x
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
		client.BackoffMinDelay = x
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
		client.BackoffMaxDelay = x
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
		client.BackoffDelayFactor = x
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

	req.HttpReq.Header.Add("Content-Type", "application/json")
	req.HttpReq.Header.Add("Accept", "application/json")
	req.HttpReq.Header.Add("User-Agent", client.UserAgent)

	// retain the request body across multiple attempts
	var body []byte
	if req.HttpReq.Body != nil {
		body, err = io.ReadAll(req.HttpReq.Body)
		if err != nil {
			return Res{}, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	if req.HttpReq.Method != http.MethodGet {
		if err := client.gate.enterWrite(ctx); err != nil {
			return Res{}, fmt.Errorf("waiting for write access: %w", err)
		}
		defer client.gate.leaveWrite()
	}

	if isReportsPath(req.HttpReq.URL.Path) {
		return client.doReports(ctx, req, body)
	}

	return client.doWithRetries(ctx, req, body)
}

// doWithRetries sends the request, retrying and reauthenticating as needed.
// The returned Res carries the HTTP status code of the last response in
// StatusCode, or 0 if no response was received, and the request ID.
func (client *Client) doWithRetries(ctx context.Context, req Req, body []byte) (Res, error) {
	// Save current auth token. In case of 401, we can check if the token has changed in the meantime
	accessToken := client.AccessToken()
	req.HttpReq.Header.Set("Authorization", "Bearer "+accessToken)

	var res Res

	for attempts := 0; ; attempts++ {
		httpRes, err := client.do(ctx, req, body)
		if err != nil {
			if ok := client.backoff(ctx, attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection error occurred: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{RequestID: req.RequestID}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] HTTP Connection failed: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}

		bodyBytes, err := io.ReadAll(httpRes.Body)
		httpRes.Body.Close()
		if err != nil {
			if ok := client.backoff(ctx, attempts); !ok {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %+v", req.RequestID, err)
				log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
				return Res{RequestID: req.RequestID}, err
			} else {
				log.Printf("[ERROR] [ReqID: %s] Cannot decode response body: %s, retries: %v", req.RequestID, err, attempts)
				continue
			}
		}

		res = Res{
			Result:     gjson.ParseBytes(bodyBytes),
			StatusCode: httpRes.StatusCode,
			RequestID:  req.RequestID,
		}

		log.Printf("[DEBUG] [ReqID: %s] HTTP Response Headers (StatusCode %d): %s", req.RequestID, httpRes.StatusCode, formatHeaders(httpRes.Header))
		if req.LogPayload {
			log.Printf("[DEBUG] [ReqID: %s] HTTP Response (StatusCode %d): %s", req.RequestID, httpRes.StatusCode, res.Raw)
		}

		if httpRes.StatusCode >= 200 && httpRes.StatusCode <= 299 {
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			break
		}

		// Check the retry budget only; each branch below does its own waiting.
		if attempts >= client.MaxRetries {
			log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
			log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
			return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)
		} else if httpRes.StatusCode == 401 {
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
		} else if isRetryableStatus(httpRes.StatusCode) {
			if wait, ok := retryAfter(httpRes.Header); ok {
				if wait > MaxRetryAfterDelay {
					log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v, Retry-After %v exceeds maximum of %v", req.RequestID, httpRes.StatusCode, wait, MaxRetryAfterDelay)
					return res, fmt.Errorf("HTTP Request failed: StatusCode %v, Retry-After %v exceeds maximum of %v", httpRes.StatusCode, wait, MaxRetryAfterDelay)
				}
				wait = jitter(wait)
				log.Printf("[WARNING] [ReqID: %s] HTTP Request failed: retries %v, StatusCode %v, waiting %v (Retry-After: %q)", req.RequestID, attempts, httpRes.StatusCode, wait, httpRes.Header.Get("Retry-After"))
				if !sleepCtx(ctx, wait) {
					return res, fmt.Errorf("HTTP Request failed: %w", ctx.Err())
				}
			} else {
				if !client.backoff(ctx, attempts) {
					return res, fmt.Errorf("HTTP Request failed: %w", ctx.Err())
				}
			}
			continue
		}

		// In case any previous conditions don't `continue`, return error
		log.Printf("[ERROR] [ReqID: %s] HTTP Request failed: StatusCode %v", req.RequestID, httpRes.StatusCode)
		log.Printf("[DEBUG] [ReqID: %s] Exit from Do method", req.RequestID)
		return res, fmt.Errorf("HTTP Request failed: StatusCode %v", httpRes.StatusCode)

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

	return client.HttpClient.Do(req.HttpReq)
}

// Get makes a GET request and returns a GJSON result.
// It does the exact request it is told to do, without pagination.
func (client *Client) Get(ctx context.Context, path string, mods ...func(*Req)) (Res, error) {
	if err := client.gate.enterRead(ctx); err != nil {
		return Res{}, fmt.Errorf("waiting for read access: %w", err)
	}
	defer client.gate.leaveRead()

	return client.get(ctx, path, mods...)
}

// GetAll makes paginated GET requests and returns all items as a single plain
// JSON array, using the Paginator registered for the path prefix, see
// pathPaginator. An empty collection returns []. An error is returned when the
// items cannot be found in the response.
func (client *Client) GetAll(ctx context.Context, path string, mods ...func(*Req)) (Res, error) {
	return client.GetAllWithPaginator(ctx, path, pathPaginator(path), mods...)
}

// GetAllWithPaginator is like GetAll, but uses the given Paginator instead of
// the one registered for the path prefix. A nil Paginator disables pagination:
// a single request is made and its response must be a plain array, otherwise
// an error is returned.
func (client *Client) GetAllWithPaginator(ctx context.Context, path string, paginate Paginator, mods ...func(*Req)) (Res, error) {
	if err := client.gate.enterRead(ctx); err != nil {
		return Res{}, fmt.Errorf("waiting for read access: %w", err)
	}
	defer client.gate.leaveRead()

	// Track all page requests under a single ID. This is done here rather than
	// in GetAll, so that callers using GetAllWithPaginator directly, and GetAll
	// which delegates here, both get a shared ID. Prepending builds a new slice,
	// so the caller's mods are never modified, and a RequestID passed by the
	// caller comes later and wins.
	mods = append([]func(*Req){RequestID(generateRequestID(8))}, mods...)

	if paginate == nil {
		res, err := client.get(ctx, path, mods...)
		if err != nil {
			return res, err
		}
		if !res.IsArray() {
			return res, fmt.Errorf("unexpected non-array response (type %s)", res.Type)
		}
		return res, nil
	}

	return paginate(ctx, client, path, mods...)
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

// DeleteWithBody makes a DELETE request with a request body.
func (client *Client) DeleteWithBody(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "DELETE", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Post makes a POST request and returns a GJSON result.
func (client *Client) Post(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "POST", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Put makes a PUT request and returns a GJSON result.
func (client *Client) Put(ctx context.Context, path, data string, mods ...func(*Req)) (Res, error) {
	req, err := client.NewReq(ctx, "PUT", path, strings.NewReader(data), mods...)
	if err != nil {
		return Res{}, err
	}
	return client.Do(req)
}

// Patch makes a PATCH request and returns a GJSON result.
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

	if client.accessToken != "" {
		if currentAccessToken == "" {
			// accessToken is present, no error reported, do nothing
			return nil
		}

		if currentAccessToken != client.accessToken {
			// accessToken has changed since the last request
			// we assume some other thread has already refreshed it, do nothing
			return nil
		}
	}

	// No accessToken or current accessToken is invalid - do the authentication
	// Whatever we have is invalid, so clear it before attempting authentication
	client.accessToken = ""

	body := strings.NewReader("grant_type=client_credentials")
	req, err := client.NewReq(ctx, "POST", "/auth/v2/token", body, NoLogPayload)
	if err != nil {
		log.Printf("[ERROR] Authentication failed: %v", err)
		return err
	}
	req.HttpReq.Header.Set("User-Agent", client.UserAgent)
	req.HttpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.HttpReq.Header.Set("Accept", "application/json")
	req.HttpReq.SetBasicAuth(client.key, client.secret)

	for attempts := 0; ; attempts++ {
		req.HttpReq.Body, err = req.HttpReq.GetBody()
		if err != nil {
			return err
		}
		httpRes, err := client.HttpClient.Do(req.HttpReq)
		if err != nil {
			if !client.backoff(ctx, attempts) {
				log.Printf("[ERROR] Authentication failed: HTTP Connection error occurred: %+v", err)
				return fmt.Errorf("authentication failed: %w", err)
			}
			log.Printf("[ERROR] Authentication failed: HTTP Connection failed: %s, retries: %v", err, attempts)
			continue
		}
		bodyBytes, _ := io.ReadAll(httpRes.Body)
		httpRes.Body.Close()

		if httpRes.StatusCode == 200 {
			bodyJson := gjson.ParseBytes(bodyBytes)
			client.accessToken = bodyJson.Get("access_token").String()
			if client.accessToken == "" {
				return fmt.Errorf("authentication failed: access token not found in response")
			}
			// Token expiration time is one hour by default. Not tracking this explicitly. Refresh will happen after failed request
			// client.expirationTime = time.Now().Add(time.Duration(bodyJson.Get("expires_in").Int()) * time.Second)
			log.Printf("[DEBUG] Authentication successful")
			return nil
		}

		if attempts >= client.MaxRetries {
			log.Printf("[ERROR] Authentication failed: retries: %v, StatusCode %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
			return fmt.Errorf("authentication failed: retries: %v, statuscode: %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
		} else if isRetryableStatus(httpRes.StatusCode) {
			if wait, ok := retryAfter(httpRes.Header); ok {
				if wait > MaxRetryAfterDelay {
					log.Printf("[ERROR] Authentication failed: StatusCode %v, Retry-After %v exceeds maximum of %v", httpRes.StatusCode, wait, MaxRetryAfterDelay)
					return fmt.Errorf("authentication failed: statuscode: %v, Retry-After %v exceeds maximum of %v", httpRes.StatusCode, wait, MaxRetryAfterDelay)
				}
				// Never retry immediately: wait at least the minimum backoff delay.
				wait = max(wait, time.Duration(client.BackoffMinDelay)*time.Second)
				log.Printf("[WARNING] Authentication failed: retries: %v, StatusCode %v, waiting %v (Retry-After: %q)", attempts, httpRes.StatusCode, wait, httpRes.Header.Get("Retry-After"))
				if !sleepCtx(ctx, wait) {
					return fmt.Errorf("authentication: %w", ctx.Err())
				}
			} else {
				if !client.backoff(ctx, attempts) {
					return fmt.Errorf("authentication: %w", ctx.Err())
				}
			}
			continue
		}

		log.Printf("[ERROR] Authentication failed: retries: %v, StatusCode %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
		return fmt.Errorf("authentication failed: retries: %v, statuscode: %v, response body: %s", attempts, httpRes.StatusCode, string(bodyBytes))
	}
}

// backoff waits following an exponential backoff algorithm.
// It reports whether the caller should retry: false means the retry budget is
// exhausted, or ctx was cancelled before or during the wait.
func (client *Client) backoff(ctx context.Context, attempts int) bool {
	log.Printf("[DEBUG] Beginning backoff method: attempt %v of %v", attempts, client.MaxRetries)
	if attempts >= client.MaxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	// Do not start a wait that is already pointless.
	if err := ctx.Err(); err != nil {
		log.Printf("[DEBUG] Exit from backoff method with return value false: %v", err)
		return false
	}

	minDelay := time.Duration(client.BackoffMinDelay) * time.Second
	maxDelay := time.Duration(client.BackoffMaxDelay) * time.Second

	min := float64(minDelay)
	backoff := min * math.Pow(client.BackoffDelayFactor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))

	if sleepCtx(ctx, backoffDuration) {
		log.Printf("[DEBUG] Exit from backoff method with return value true")
		return true
	}
	log.Printf("[DEBUG] Exit from backoff method with return value false: %v", ctx.Err())
	return false
}
