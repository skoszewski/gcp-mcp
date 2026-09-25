package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/skoszewski/gcp-mcp/internal/gcp"
)

// fixedAuthorizer authorizes every request with a fixed bearer token.
type fixedAuthorizer struct{}

func (fixedAuthorizer) Authorize(_ context.Context, request *http.Request) error {
	request.Header.Set("Authorization", "Bearer token")
	return nil
}

func (fixedAuthorizer) Method() string  { return "fixed" }
func (fixedAuthorizer) Project() string { return "home-project" }

// fakeResponses maps a request's original URL to the status and body the fake API answers with.
type fakeResponses map[string]struct {
	status int
	body   string
}

// connect serves the tools against a fake Google Cloud API answering with responses, and returns
// a client session and the request bodies the API received, keyed by URL.
func connect(t *testing.T, responses fakeResponses) (*mcp.ClientSession, map[string]string) {
	t.Helper()
	bodies := map[string]string{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original := r.Header.Get("X-Original-URL")
		body, _ := io.ReadAll(r.Body)
		bodies[original] = string(body)
		response, found := responses[original]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"message":"not found","status":"NOT_FOUND"}}`)
			return
		}
		w.WriteHeader(response.status)
		io.WriteString(w, response.body)
	}))
	t.Cleanup(api.Close)
	target, _ := url.Parse(api.URL)
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("X-Original-URL", r.URL.String())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})

	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server, &gcp.Client{HTTP: &http.Client{Transport: transport}, Auth: fixedAuthorizer{}})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, bodies
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// call calls a tool and returns its structured result as JSON, failing the test on an error
// result unless wantError is set.
func call(t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any, wantError bool) string {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if result.IsError != wantError {
		t.Fatalf("%s: IsError = %v, content %+v", name, result.IsError, result.Content)
	}
	if wantError {
		return result.Content[0].(*mcp.TextContent).Text
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestQueryCloudLogging(t *testing.T) {
	session, bodies := connect(t, fakeResponses{
		"https://logging.googleapis.com/v2/entries:list": {200, `{"entries":[{"insertId":"a","jsonPayload":{"k":"v"}}]}`},
	})
	got := call(t, session, "gcp_query_cloud_logging", map[string]any{
		"filter_expression": "protoPayload.status.code=7", "start": "2026-09-01T00:00:00Z",
	}, false)
	want := `{"entries":[{"insert_id":"a","log_name":null,"payload":{"k":"v"},"severity":null,"timestamp":null}]}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	var request struct {
		ResourceNames []string `json:"resourceNames"`
		Filter        string   `json:"filter"`
	}
	if err := json.Unmarshal([]byte(bodies["https://logging.googleapis.com/v2/entries:list"]), &request); err != nil {
		t.Fatal(err)
	}
	if request.ResourceNames[0] != "projects/home-project" || request.Filter != `protoPayload.status.code=7 AND timestamp>="2026-09-01T00:00:00Z"` {
		t.Errorf("request = %+v", request)
	}

	call(t, session, "gcp_query_cloud_logging", map[string]any{"filter_expression": "x", "scope": "other"}, false)
	if body := bodies["https://logging.googleapis.com/v2/entries:list"]; !strings.Contains(body, `"resourceNames":["projects/other"]`) ||
		!strings.Contains(body, `x AND timestamp`) {
		t.Errorf("request body = %s", body)
	}

	if text := call(t, session, "gcp_query_cloud_logging", map[string]any{"filter_expression": " "}, true); text != noFilterMessage {
		t.Errorf("empty filter error = %q", text)
	}
}

func TestGetServicePerimeterPolicy(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://accesscontextmanager.googleapis.com/v1/accessPolicies/1/servicePerimeters/p": {200,
			`{"title":"P","status":{"restrictedServices":["storage.googleapis.com"],"ingressPolicies":[{"ingressFrom":{}}]}}`},
	})
	got := call(t, session, "gcp_get_service_perimeter_policy", map[string]any{"service_perimeter": "accessPolicies/1/servicePerimeters/p"}, false)
	want := `{"perimeter_type":"PERIMETER_TYPE_REGULAR","spec":null,"status":{"egress_policies":[],"ingress_policies":[{"ingressFrom":{}}],` +
		`"resources":[],"restricted_services":["storage.googleapis.com"],"vpc_accessible_services_allowed":[],` +
		`"vpc_accessible_services_restriction_enabled":false},"title":"P","use_explicit_dry_run_spec":false}`
	if got != want {
		t.Errorf("result = %s", got)
	}
}

func TestGetAccessLevel(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://accesscontextmanager.googleapis.com/v1/accessPolicies/1/accessLevels/l": {200,
			`{"title":"L","basic":{"conditions":[{"ipSubnetworks":["10.0.0.0/8"],"negate":true}]}}`},
	})
	got := call(t, session, "gcp_get_access_level", map[string]any{"access_level": "accessPolicies/1/accessLevels/l"}, false)
	want := `{"combining_function":"AND","conditions":[{"device_policy":null,"ip_subnetworks":["10.0.0.0/8"],"members":[],"negate":true,"regions":[]}],"title":"L"}`
	if got != want {
		t.Errorf("result = %s", got)
	}
}

func TestIAMTools(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy": {200, `{"bindings":[
			{"role":"roles/viewer","members":["user:a@example.com","user:b@example.com"]},
			{"role":"roles/editor","members":["user:a@example.com"],"condition":{"title":"t","expression":"true"}},
			{"role":"roles/owner"}]}`},
	})
	got := call(t, session, "gcp_get_iam_roles_for_member", map[string]any{"resource": "p", "member": "user:a@example.com"}, false)
	want := `{"roles":[{"condition":null,"role":"roles/viewer"},{"condition":{"expression":"true","title":"t"},"role":"roles/editor"}]}`
	if got != want {
		t.Errorf("roles = %s", got)
	}
	got = call(t, session, "gcp_get_iam_policy", map[string]any{"resource": "p"}, false)
	if !strings.Contains(got, `{"condition":null,"members":[],"role":"roles/owner"}`) {
		t.Errorf("policy = %s", got)
	}
}

func TestResolveProjectIdentifiers(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v3/projects/123": {200, `{"name":"projects/123","projectId":"p","displayName":"P"}`},
	})
	got := call(t, session, "gcp_resolve_project_identifiers", map[string]any{"project": " 123 , missing,"}, false)
	want := `{"projects":[{"display_name":"P","project_id":"p","project_number":"123","requested":"123"},` +
		`{"error":"request to https://cloudresourcemanager.googleapis.com/v3/projects/missing failed: 404 Not Found: NOT_FOUND: not found","requested":"missing"}]}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	if text := call(t, session, "gcp_resolve_project_identifiers", map[string]any{"project": " , "}, true); text != noProjectMessage {
		t.Errorf("empty project error = %q", text)
	}
}
