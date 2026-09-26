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

func TestIAMToolsOnFolder(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v3/folders/7:getIamPolicy": {200, `{"bindings":[{"role":"roles/viewer","members":["user:a@example.com"]}]}`},
	})
	got := call(t, session, "gcp_get_iam_roles_for_member", map[string]any{"resource": "folders/7", "member": "user:a@example.com"}, false)
	if got != `{"roles":[{"condition":null,"role":"roles/viewer"}]}` {
		t.Errorf("roles = %s", got)
	}
}

func TestGetRole(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://iam.googleapis.com/v1/roles/storage.admin": {200, `{"name":"roles/storage.admin","title":"Storage Admin","stage":"GA","includedPermissions":["storage.buckets.get"]}`},
	})
	got := call(t, session, "gcp_get_role", map[string]any{"role": "storage.admin"}, false)
	want := `{"deleted":false,"description":null,"included_permissions":["storage.buckets.get"],"name":"roles/storage.admin","stage":"GA","title":"Storage Admin"}`
	if got != want {
		t.Errorf("result = %s", got)
	}
}

func TestGetProjectAncestry(t *testing.T) {
	session, bodies := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v1/projects/p:getAncestry": {200,
			`{"ancestor":[{"resourceId":{"type":"project","id":"p"}},{"resourceId":{"type":"folder","id":"7"}},{"resourceId":{"type":"organization","id":"9"}}]}`},
	})
	got := call(t, session, "gcp_get_project_ancestry", map[string]any{"project": "projects/p"}, false)
	want := `{"ancestors":[{"id":"p","type":"project"},{"id":"7","type":"folder"},{"id":"9","type":"organization"}]}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	if body := bodies["https://cloudresourcemanager.googleapis.com/v1/projects/p:getAncestry"]; body != `{}` {
		t.Errorf("request body = %s", body)
	}
}

func TestTroubleshootIAMPermission(t *testing.T) {
	session, bodies := connect(t, fakeResponses{
		"https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot": {200, `{"overallAccessState":"CANNOT_ACCESS",
			"allowPolicyExplanation":{"allowAccessState":"ALLOW_ACCESS_STATE_NOT_GRANTED","explainedPolicies":[{"fullResourceName":"//cloudresourcemanager.googleapis.com/projects/p",
				"allowAccessState":"ALLOW_ACCESS_STATE_NOT_GRANTED","policy":{"bindings":[]},"bindingExplanations":[
				{"role":"roles/viewer","rolePermission":"ROLE_PERMISSION_NOT_INCLUDED"},
				{"role":"roles/storage.admin","rolePermission":"ROLE_PERMISSION_INCLUDED","combinedMembership":{"membership":"MEMBERSHIP_NOT_MATCHED"}}]}]},
			"denyPolicyExplanation":{"denyAccessState":"DENY_ACCESS_STATE_NOT_DENIED"}}`},
	})
	got := call(t, session, "gcp_troubleshoot_iam_permission", map[string]any{
		"principal": "serviceAccount:sa@p.iam.gserviceaccount.com", "resource": "p", "permission": "storage.buckets.get",
	}, false)
	want := `{"allow_access_state":"ALLOW_ACCESS_STATE_NOT_GRANTED","allow_policies":[{"allow_access_state":"ALLOW_ACCESS_STATE_NOT_GRANTED","bindings":[` +
		`{"allowAccessState":null,"combinedMembership":{"membership":"MEMBERSHIP_NOT_MATCHED"},"condition":null,"conditionExplanation":null,"memberships":null,` +
		`"relevance":null,"role":"roles/storage.admin","rolePermission":"ROLE_PERMISSION_INCLUDED"}],"full_resource_name":"//cloudresourcemanager.googleapis.com/projects/p","relevance":null}],` +
		`"deny_policy_explanation":{"denyAccessState":"DENY_ACCESS_STATE_NOT_DENIED"},"overall_access_state":"CANNOT_ACCESS"}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	want = `{"accessTuple":{"principal":"sa@p.iam.gserviceaccount.com","fullResourceName":"//cloudresourcemanager.googleapis.com/projects/p","permission":"storage.buckets.get"}}`
	if body := bodies["https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot"]; body != want {
		t.Errorf("request body = %s", body)
	}
}

func TestGetServiceAccount(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://iam.googleapis.com/v1/projects/-/serviceAccounts/1234": {200,
			`{"name":"projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com","email":"sa@p.iam.gserviceaccount.com","uniqueId":"1234","projectId":"p"}`},
		"https://iam.googleapis.com/v1/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3": {200,
			`{"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["user:a@example.com"]}]}`},
	})
	got := call(t, session, "gcp_get_service_account", map[string]any{"service_account": "1234"}, false)
	want := `{"description":null,"disabled":false,"display_name":null,"email":"sa@p.iam.gserviceaccount.com",` +
		`"iam_bindings":[{"condition":null,"members":["user:a@example.com"],"role":"roles/iam.serviceAccountTokenCreator"}],` +
		`"name":"projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com","oauth2_client_id":null,"project_id":"p","unique_id":"1234"}`
	if got != want {
		t.Errorf("result = %s", got)
	}
}

func TestGetServiceAccountPolicyError(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://iam.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com": {200,
			`{"name":"projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"}`},
	})
	got := call(t, session, "gcp_get_service_account", map[string]any{"service_account": "serviceAccount:sa@p.iam.gserviceaccount.com"}, false)
	if !strings.Contains(got, `"iam_bindings":[]`) || !strings.Contains(got, `"iam_policy_error":"request to https://iam.googleapis.com/v1/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com:getIamPolicy`) {
		t.Errorf("result = %s", got)
	}
}

func TestListServicePerimeters(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v3/projects/p": {200, `{"name":"projects/123","projectId":"p"}`},
		"https://accesscontextmanager.googleapis.com/v1/accessPolicies/5/servicePerimeters": {200, `{"servicePerimeters":[
			{"name":"accessPolicies/5/servicePerimeters/a","title":"A","status":{"resources":["projects/123"]}},
			{"name":"accessPolicies/5/servicePerimeters/b","perimeterType":"PERIMETER_TYPE_BRIDGE","spec":{"resources":["projects/123","projects/456"]}},
			{"name":"accessPolicies/5/servicePerimeters/c","status":{"resources":["projects/456"]}}]}`},
	})
	got := call(t, session, "gcp_list_service_perimeters", map[string]any{"access_policy": "5", "project": "p"}, false)
	want := `{"service_perimeters":[{"dry_run_resources":[],"name":"accessPolicies/5/servicePerimeters/a","perimeter_type":"PERIMETER_TYPE_REGULAR","resources":["projects/123"],"title":"A"},` +
		`{"dry_run_resources":["projects/123","projects/456"],"name":"accessPolicies/5/servicePerimeters/b","perimeter_type":"PERIMETER_TYPE_BRIDGE","resources":[],"title":null}]}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	if got := call(t, session, "gcp_list_service_perimeters", map[string]any{"access_policy": "accessPolicies/5"}, false); strings.Count(got, `"name"`) != 3 {
		t.Errorf("unfiltered result = %s", got)
	}
}

func TestListAccessPolicies(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations%2F9": {200,
			`{"accessPolicies":[{"name":"accessPolicies/5","title":"T","parent":"organizations/9"}]}`},
	})
	got := call(t, session, "gcp_list_access_policies", map[string]any{"organization": "9"}, false)
	if got != `{"access_policies":[{"name":"accessPolicies/5","parent":"organizations/9","scopes":[],"title":"T"}]}` {
		t.Errorf("result = %s", got)
	}
}

func TestGetEffectiveOrgPolicy(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://orgpolicy.googleapis.com/v2/projects/p/policies/iam.allowedPolicyMemberDomains:getEffectivePolicy": {200,
			`{"name":"projects/123/policies/iam.allowedPolicyMemberDomains","spec":{"rules":[{"values":{"allowedValues":["C0abc"]}}]}}`},
	})
	got := call(t, session, "gcp_get_effective_org_policy", map[string]any{"resource": "p", "constraint": "constraints/iam.allowedPolicyMemberDomains"}, false)
	want := `{"dry_run_spec":null,"name":"projects/123/policies/iam.allowedPolicyMemberDomains","spec":{"rules":[{"values":{"allowedValues":["C0abc"]}}]}}`
	if got != want {
		t.Errorf("result = %s", got)
	}
}

func TestSearchIAMPoliciesTool(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudasset.googleapis.com/v1/organizations/9:searchAllIamPolicies?pageSize=500&query=policy%3Aa%40example.com": {200,
			`{"results":[{"resource":"//storage.googleapis.com/b","assetType":"storage.googleapis.com/Bucket","project":"projects/123",
				"policy":{"bindings":[{"role":"roles/storage.objectViewer","members":["user:a@example.com"]}]}}]}`},
	})
	got := call(t, session, "gcp_search_iam_policies", map[string]any{"scope": "organizations/9", "query": "policy:a@example.com"}, false)
	want := `{"results":[{"asset_type":"storage.googleapis.com/Bucket","bindings":[{"condition":null,"members":["user:a@example.com"],"role":"roles/storage.objectViewer"}],` +
		`"folders":[],"organization":null,"project":"projects/123","resource":"//storage.googleapis.com/b"}]}`
	if got != want {
		t.Errorf("result = %s", got)
	}
	if text := call(t, session, "gcp_search_iam_policies", map[string]any{"scope": "p", "query": " "}, true); text != noQueryMessage {
		t.Errorf("empty query error = %q", text)
	}
}

func TestHierarchyListTools(t *testing.T) {
	session, _ := connect(t, fakeResponses{
		"https://cloudresourcemanager.googleapis.com/v3/organizations:search": {200,
			`{"organizations":[{"name":"organizations/9","displayName":"example.com","directoryCustomerId":"C0abc","state":"ACTIVE"}]}`},
		"https://cloudresourcemanager.googleapis.com/v3/folders?parent=organizations%2F9": {200,
			`{"folders":[{"name":"folders/7","displayName":"Prod","parent":"organizations/9","state":"ACTIVE"}]}`},
		"https://cloudresourcemanager.googleapis.com/v3/projects:search?query=labels.env%3Aprod": {200,
			`{"projects":[{"name":"projects/123","projectId":"p","displayName":"P","parent":"folders/7","state":"ACTIVE","labels":{"env":"prod"}}]}`},
	})
	got := call(t, session, "gcp_list_organizations", map[string]any{}, false)
	if got != `{"organizations":[{"directory_customer_id":"C0abc","display_name":"example.com","name":"organizations/9","state":"ACTIVE"}]}` {
		t.Errorf("organizations = %s", got)
	}
	got = call(t, session, "gcp_list_folders", map[string]any{"parent": "organizations/9"}, false)
	if got != `{"folders":[{"display_name":"Prod","name":"folders/7","parent":"organizations/9","state":"ACTIVE"}]}` {
		t.Errorf("folders = %s", got)
	}
	got = call(t, session, "gcp_list_projects", map[string]any{"query": "labels.env:prod"}, false)
	if got != `{"projects":[{"display_name":"P","labels":{"env":"prod"},"parent":"folders/7","project_id":"p","project_number":"123","state":"ACTIVE"}]}` {
		t.Errorf("projects = %s", got)
	}
	if text := call(t, session, "gcp_list_projects", map[string]any{"parent": "folders/7", "query": "x"}, true); text != parentAndQueryMessage {
		t.Errorf("parent and query error = %q", text)
	}
}
