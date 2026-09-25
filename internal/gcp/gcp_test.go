package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/compute/metadata"
)

// staticAuthorizer authorizes every request with a fixed bearer token and quota project.
type staticAuthorizer struct{}

func (staticAuthorizer) Authorize(_ context.Context, request *http.Request) error {
	request.Header.Set("Authorization", "Bearer server-token")
	request.Header.Set(quotaProjectHeader, "quota-project")
	return nil
}

func (staticAuthorizer) Method() string  { return "static" }
func (staticAuthorizer) Project() string { return "default-project" }

// recorded is one request the fake API received.
type recorded struct {
	method        string
	url           string
	authorization string
	quotaProject  string
	body          string
}

// fakeAPI serves handler for every Google Cloud host, records each request, and returns a client
// whose requests reach it.
func fakeAPI(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body string)) (*Client, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	requests := &[]recorded{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*requests = append(*requests, recorded{
			method: r.Method, url: r.Header.Get("X-Original-URL"), authorization: r.Header.Get("Authorization"),
			quotaProject: r.Header.Get(quotaProjectHeader), body: string(body),
		})
		mu.Unlock()
		handler(w, r, string(body))
	}))
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("X-Original-URL", r.URL.String())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})
	return &Client{HTTP: &http.Client{Transport: transport}, Auth: staticAuthorizer{}}, requests
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseFreshness(t *testing.T) {
	for freshness, want := range map[string]time.Duration{"30s": 30 * time.Second, "15m": 15 * time.Minute, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour} {
		if got, err := ParseFreshness(freshness); err != nil || got != want {
			t.Errorf("ParseFreshness(%q) = %v, %v; want %v", freshness, got, err, want)
		}
	}
	for _, freshness := range []string{"", "24", "1w", "h", "-1h", " 1h"} {
		if _, err := ParseFreshness(freshness); err == nil {
			t.Errorf("ParseFreshness(%q): expected an error", freshness)
		}
	}
}

func TestTimeFilter(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		freshness, start, end, want string
	}{
		{"", "", "", ""},
		{"2h", "", "", `timestamp>="2026-09-25T10:00:00Z"`},
		{"2h", "2026-09-01T00:00:00Z", "", `timestamp>="2026-09-01T00:00:00Z"`},
		{"", "", "2026-09-02T00:00:00Z", `timestamp<="2026-09-02T00:00:00Z"`},
		{"", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", `timestamp>="2026-09-01T00:00:00Z" AND timestamp<="2026-09-02T00:00:00Z"`},
	}
	for _, c := range cases {
		if got, err := TimeFilter(c.freshness, c.start, c.end, now); err != nil || got != c.want {
			t.Errorf("TimeFilter(%q, %q, %q) = %q, %v; want %q", c.freshness, c.start, c.end, got, err, c.want)
		}
	}
	if _, err := TimeFilter("soon", "", "", now); err == nil {
		t.Error("TimeFilter with an invalid freshness: expected an error")
	}
}

func TestWithDefaultWindow(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if got := WithDefaultWindow("severity>=ERROR", now); got != `severity>=ERROR AND timestamp>="2026-09-24T12:00:00Z"` {
		t.Errorf("without a timestamp: %q", got)
	}
	filter := `severity>=ERROR AND Timestamp>="2026-01-01T00:00:00Z"`
	if got := WithDefaultWindow(filter, now); got != filter {
		t.Errorf("with a timestamp: %q", got)
	}
}

func TestLogEntriesPaging(t *testing.T) {
	client, requests := fakeAPI(t, func(w http.ResponseWriter, _ *http.Request, body string) {
		if strings.Contains(body, `"pageToken":"next"`) {
			io.WriteString(w, `{"entries":[{"insertId":"b","textPayload":"text"}]}`)
			return
		}
		io.WriteString(w, `{"entries":[{"insertId":"a","timestamp":"2026-09-25T10:00:00Z","severity":"ERROR","logName":"projects/p/logs/x","protoPayload":{"@type":"t"}}],"nextPageToken":"next"}`)
	})
	entries, err := client.LogEntries(context.Background(), "projects/p", "severity>=ERROR")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || *entries[0].InsertID != "a" || *entries[1].InsertID != "b" {
		t.Fatalf("entries = %+v", entries)
	}
	if payload, ok := entries[0].Payload().(map[string]any); !ok || payload["@type"] != "t" {
		t.Errorf("proto payload = %#v", entries[0].Payload())
	}
	if entries[1].Payload() != "text" {
		t.Errorf("text payload = %#v", entries[1].Payload())
	}

	if len(*requests) != 2 {
		t.Fatalf("%d requests", len(*requests))
	}
	first := (*requests)[0]
	if first.method != http.MethodPost || first.url != "https://logging.googleapis.com/v2/entries:list" {
		t.Errorf("request = %s %s", first.method, first.url)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(first.body), &body); err != nil {
		t.Fatal(err)
	}
	if body["filter"] != "severity>=ERROR" || body["orderBy"] != "timestamp desc" || body["pageSize"] != float64(LogEntriesPageSize) ||
		body["resourceNames"].([]any)[0] != "projects/p" || body["pageToken"] != nil {
		t.Errorf("body = %s", first.body)
	}
	if first.authorization != "Bearer server-token" || first.quotaProject != "quota-project" {
		t.Errorf("headers = %q, %q", first.authorization, first.quotaProject)
	}
}

func TestRequestAuthorizationOverride(t *testing.T) {
	client, requests := fakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		io.WriteString(w, `{"name":"projects/1"}`)
	})
	ctx := WithAuthorization(context.Background(), "Bearer client-token")
	if _, err := client.Project(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.authorization != "Bearer client-token" || got.quotaProject != "" {
		t.Errorf("headers = %q, %q", got.authorization, got.quotaProject)
	}
}

func TestRetryAndRequestError(t *testing.T) {
	retryBackoff = time.Millisecond
	calls := 0
	client, _ := fakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		calls++
		switch calls {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			io.WriteString(w, `{"name":"projects/123","projectId":"p","displayName":"P"}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}`)
		}
	})
	project, err := client.Project(context.Background(), "p")
	if err != nil || project.ProjectNumber() != "123" || calls != 2 {
		t.Fatalf("Project() = %+v, %v after %d calls", project, err, calls)
	}

	_, err = client.Project(context.Background(), "q")
	var requestError *RequestError
	if !errors.As(err, &requestError) || requestError.StatusCode != http.StatusForbidden ||
		err.Error() != "request to https://cloudresourcemanager.googleapis.com/v3/projects/q failed: 403 Forbidden: PERMISSION_DENIED: denied" {
		t.Errorf("error = %v", err)
	}
	if calls != 3 {
		t.Errorf("a 403 was retried: %d calls", calls)
	}
}

func TestNameValidation(t *testing.T) {
	client, requests := fakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		io.WriteString(w, `{}`)
	})
	ctx := context.Background()
	if _, err := client.ServicePerimeter(ctx, "servicePerimeters/x"); err == nil {
		t.Error("ServicePerimeter with a short name: expected an error")
	}
	if _, err := client.AccessLevel(ctx, "accessPolicies/1/servicePerimeters/x"); err == nil {
		t.Error("AccessLevel with a perimeter name: expected an error")
	}
	if _, err := client.Project(ctx, "a/b"); err == nil {
		t.Error("Project with a slash: expected an error")
	}
	if len(*requests) != 0 {
		t.Errorf("%d requests sent for invalid names", len(*requests))
	}

	if _, err := client.AccessLevel(ctx, "accessPolicies/1/accessLevels/a b"); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0].url; got != "https://accesscontextmanager.googleapis.com/v1/accessPolicies/1/accessLevels/a%20b" {
		t.Errorf("url = %s", got)
	}
}

func TestProjectIAMBindingsCache(t *testing.T) {
	client, requests := fakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		io.WriteString(w, `{"bindings":[{"role":"roles/viewer","members":["user:a@example.com"]}]}`)
	})
	ctx := context.Background()
	for range 2 {
		bindings, err := client.ProjectIAMBindings(ctx, "p")
		if err != nil || len(bindings) != 1 || *bindings[0].Role != "roles/viewer" {
			t.Fatalf("ProjectIAMBindings() = %+v, %v", bindings, err)
		}
	}
	if len(*requests) != 1 {
		t.Errorf("%d requests for one project and credential", len(*requests))
	}
	first := (*requests)[0]
	if first.url != "https://cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy" ||
		first.body != `{"options":{"requestedPolicyVersion":3}}` {
		t.Errorf("request = %s %s", first.url, first.body)
	}

	if _, err := client.ProjectIAMBindings(WithAuthorization(ctx, "Bearer other"), "p"); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 2 {
		t.Errorf("bindings reused across credentials: %d requests", len(*requests))
	}
}

func TestNewAuthorizerCloudSDKConfig(t *testing.T) {
	configDir := t.TempDir()
	file := `{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","quota_project_id":"quota"}`
	if err := os.WriteFile(filepath.Join(configDir, wellKnownFile), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"CLOUDSDK_CONFIG": configDir, "GOOGLE_CLOUD_PROJECT": "p"}
	authorizer, err := NewAuthorizer(context.Background(), AuthADC, func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	adc := authorizer.(*adcAuthorizer)
	if adc.method != "Application Default Credentials (authorized_user)" || adc.quotaProject != "quota" || adc.project != "p" {
		t.Errorf("authorizer = %+v", adc)
	}

	env["CLOUDSDK_CONFIG"] = configDir + "/missing"
	if !metadata.OnGCE() {
		if _, err := NewAuthorizer(context.Background(), AuthADC, func(name string) string { return env[name] }); err == nil {
			t.Error("CLOUDSDK_CONFIG without a credentials file: expected an error")
		}
	}
}

func TestNewAuthorizerAccessToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN": " value-token\n", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": tokenFile,
		"GOOGLE_CLOUD_PROJECT": "p", "GOOGLE_CLOUD_QUOTA_PROJECT": "quota",
	}
	getenv := func(name string) string { return env[name] }
	authorize := func(method string) (string, string) {
		t.Helper()
		authorizer, err := NewAuthorizer(context.Background(), method, getenv)
		if err != nil {
			t.Fatalf("NewAuthorizer(%s): %v", method, err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		if err := authorizer.Authorize(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		return request.Header.Get("Authorization"), request.Header.Get(quotaProjectHeader)
	}

	if header, quota := authorize(AuthAuto); header != "Bearer value-token" || quota != "quota" {
		t.Errorf("token value: %q, %q", header, quota)
	}
	delete(env, "CLOUDSDK_AUTH_ACCESS_TOKEN")
	if header, _ := authorize(AuthAccessToken); header != "Bearer file-token" {
		t.Errorf("token file: %q", header)
	}
	if err := os.WriteFile(tokenFile, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if header, _ := authorize(AuthAuto); header != "Bearer rotated" {
		t.Errorf("rotated token file: %q", header)
	}

	delete(env, "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE")
	if _, err := NewAuthorizer(context.Background(), AuthAccessToken, getenv); err == nil {
		t.Error("--auth access-token without a token: expected an error")
	}
}

func TestNewAuthorizerNone(t *testing.T) {
	env := map[string]string{"GCLOUD_PROJECT": "legacy"}
	authorizer, err := NewAuthorizer(context.Background(), AuthNone, func(name string) string { return env[name] })
	if err != nil || authorizer.Project() != "legacy" {
		t.Fatalf("NewAuthorizer(none) = %v, %v", authorizer, err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := authorizer.Authorize(context.Background(), request); err == nil {
		t.Error("none authorizer: expected an error")
	}
	if _, err := NewAuthorizer(context.Background(), "bogus", func(string) string { return "" }); err == nil {
		t.Error("unknown method: expected an error")
	}
}
