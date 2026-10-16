package secureaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// newTestServer starts a server that authenticates every token request and
// answers paths listed in ok with 200, everything else with failStatus. It
// records the path of every non-auth request.
func newTestServer(t *testing.T, failStatus int, ok ...string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v2/token" {
			w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		for _, p := range ok {
			if r.URL.Path == p {
				w.Write([]byte(`{"data":{}}`))
				return
			}
		}
		w.WriteHeader(failStatus)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func newTestClient(t *testing.T, url string) *Client {
	t.Helper()
	client, err := NewClient(url, "key", "secret", BackoffMinDelay(0), BackoffMaxDelay(0), MaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	return &client
}

func equalPaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReportsPrefixDiscovery(t *testing.T) {
	srv, paths := newTestServer(t, http.StatusForbidden, "/reports.eu/v2/applications", "/reports.eu/v2/other")
	client := newTestClient(t, srv.URL)
	ctx := context.Background()

	if _, err := client.Get(ctx, "/reports/v2/applications"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	want := []string{"/reports/v2/applications", "/reports.us/v2/applications", "/reports.eu/v2/applications"}
	if got := paths(); !equalPaths(got, want) {
		t.Fatalf("discovery paths = %v, want %v", got, want)
	}

	// The discovered prefix is reused by other requests, including concurrent ones.
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.Get(ctx, "/reports/v2/other"); err != nil {
				t.Errorf("later request: %v", err)
			}
		}()
	}
	wg.Wait()
	for _, p := range paths()[len(want):] {
		if p != "/reports.eu/v2/other" {
			t.Fatalf("later request used %s, want /reports.eu/v2/other", p)
		}
	}
}

func TestReportsPrefixFirstMatchWins(t *testing.T) {
	srv, paths := newTestServer(t, http.StatusForbidden, "/reports/v2/applications", "/reports.us/v2/applications")
	client := newTestClient(t, srv.URL)

	if _, err := client.Get(context.Background(), "/reports/v2/applications"); err != nil {
		t.Fatal(err)
	}
	if got, want := paths(), []string{"/reports/v2/applications"}; !equalPaths(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestReportsPrefixNotSavedOnFailure(t *testing.T) {
	srv, paths := newTestServer(t, http.StatusForbidden, "/reports.us/v2/applications")
	client := newTestClient(t, srv.URL)
	ctx := context.Background()

	if _, err := client.Get(ctx, "/reports/v2/missing"); err == nil {
		t.Fatal("expected error when every prefix returns 403")
	}
	if client.reports.prefix != "" {
		t.Fatalf("prefix saved after failure: %q", client.reports.prefix)
	}

	// Discovery runs again on the next request.
	if _, err := client.Get(ctx, "/reports/v2/applications"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/reports/v2/missing", "/reports.us/v2/missing", "/reports.eu/v2/missing",
		"/reports/v2/applications", "/reports.us/v2/applications",
	}
	if got := paths(); !equalPaths(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestReportsPrefixStopsOnOtherError(t *testing.T) {
	srv, paths := newTestServer(t, http.StatusNotFound, "/reports.us/v2/applications")
	client := newTestClient(t, srv.URL)

	if _, err := client.Get(context.Background(), "/reports/v2/applications"); err == nil {
		t.Fatal("expected error")
	}
	if got, want := paths(), []string{"/reports/v2/applications"}; !equalPaths(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	if client.reports.prefix != "" {
		t.Fatalf("prefix saved after failure: %q", client.reports.prefix)
	}
}

func TestNonReportsPathUnchanged(t *testing.T) {
	srv, paths := newTestServer(t, http.StatusNotFound, "/policies/v2/rules", "/reportsfoo/v2/x")
	client := newTestClient(t, srv.URL)
	ctx := context.Background()

	for _, p := range []string{"/policies/v2/rules", "/reportsfoo/v2/x"} {
		if _, err := client.Get(ctx, p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if got, want := paths(), []string{"/policies/v2/rules", "/reportsfoo/v2/x"}; !equalPaths(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}
