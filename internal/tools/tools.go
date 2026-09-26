// Package tools registers the Google Cloud investigation MCP tools.
package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/skoszewski/gcp-mcp/internal/gcp"
)

const (
	defaultPerimeterType     = "PERIMETER_TYPE_REGULAR"
	defaultCombiningFunction = "AND"
)

// handlers implements the tools on top of a Google Cloud client.
type handlers struct {
	client *gcp.Client
}

// Register adds every Google Cloud tool to server and returns their names in registration
// order.
func Register(server *mcp.Server, client *gcp.Client) []string {
	h := &handlers{client: client}
	return []string{
		addTool(server, "gcp_query_cloud_logging", queryCloudLoggingDescription, h.queryCloudLogging),
		addTool(server, "gcp_get_service_perimeter_policy", getServicePerimeterPolicyDescription, h.getServicePerimeterPolicy),
		addTool(server, "gcp_get_access_level", getAccessLevelDescription, h.getAccessLevel),
		addTool(server, "gcp_get_iam_policy", getIAMPolicyDescription, h.getIAMPolicy),
		addTool(server, "gcp_get_iam_roles_for_member", getIAMRolesForMemberDescription, h.getIAMRolesForMember),
		addTool(server, "gcp_resolve_project_identifiers", resolveProjectIdentifiersDescription, h.resolveProjectIdentifiers),
		addTool(server, "gcp_get_role", getRoleDescription, h.getRole),
		addTool(server, "gcp_get_project_ancestry", getProjectAncestryDescription, h.getProjectAncestry),
		addTool(server, "gcp_troubleshoot_iam_permission", troubleshootIAMPermissionDescription, h.troubleshootIAMPermission),
		addTool(server, "gcp_get_service_account", getServiceAccountDescription, h.getServiceAccount),
		addTool(server, "gcp_list_access_policies", listAccessPoliciesDescription, h.listAccessPolicies),
		addTool(server, "gcp_list_service_perimeters", listServicePerimetersDescription, h.listServicePerimeters),
		addTool(server, "gcp_get_effective_org_policy", getEffectiveOrgPolicyDescription, h.getEffectiveOrgPolicy),
		addTool(server, "gcp_search_iam_policies", searchIAMPoliciesDescription, h.searchIAMPolicies),
		addTool(server, "gcp_list_organizations", listOrganizationsDescription, h.listOrganizations),
		addTool(server, "gcp_list_folders", listFoldersDescription, h.listFolders),
		addTool(server, "gcp_list_projects", listProjectsDescription, h.listProjects),
	}
}

// hierarchyName returns a project, folder or organization argument as a resource name, taking a
// value without a slash as a project ID or number.
func hierarchyName(value string) string {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		return "projects/" + value
	}
	return value
}

// principalEmail returns an IAM member without its user: or serviceAccount: type prefix.
func principalEmail(member string) string {
	member = strings.TrimSpace(member)
	for _, prefix := range []string{"user:", "serviceAccount:"} {
		member = strings.TrimPrefix(member, prefix)
	}
	return member
}

// addTool registers handler as the tool name, with the input schema inferred from In. An
// Authorization header on the HTTP request carrying the call replaces the configured credential
// for that call. Every call is logged at debug level, and a handler error reaches the caller as
// a tool error result.
func addTool[In, Out any](server *mcp.Server, name, description string, handler func(context.Context, In) (Out, error)) string {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("tool %s: %v", name, err))
	}

	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, InputSchema: schema},
		func(ctx context.Context, request *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
			slog.Debug("tool call", "tool", name, "arguments", string(request.Params.Arguments))
			if request.Extra != nil {
				if authorization := request.Extra.Header.Get("Authorization"); authorization != "" {
					ctx = gcp.WithAuthorization(ctx, authorization)
				}
			}
			output, err := handler(ctx, input)
			if err != nil {
				slog.Debug("tool failed", "tool", name, "error", err)
			}
			return nil, output, err
		})
	return name
}

// orEmpty returns values, or an empty slice when it is nil, which a result reports as [].
func orEmpty[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

type queryCloudLoggingInput struct {
	FilterExpression string `json:"filter_expression" jsonschema:"a Cloud Logging filter expression, e.g. 'protoPayload.metadata.\"@type\"=\"type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata\"' for VPC SC denials (add 'protoPayload.metadata.vpcServiceControlsUniqueId=\"<id>\"' to target one specific violation), 'protoPayload.status.code=7' for permission-denied entries generally, or 'protoPayload.methodName=\"SetIamPolicy\"' for IAM policy change history."`
	Scope            string `json:"scope,omitempty" jsonschema:"Cloud Logging resource_names value, e.g. \"projects/<gcp-project-id>\". Omit it to search the project the investigation's own credentials belong to, which is where the activity being investigated is normally logged; pass it only when the entries point at a different project. A bare project ID is accepted and prefixed with \"projects/\"."`
	Freshness        string `json:"freshness,omitempty" jsonschema:"lookback duration (e.g. \"24h\", \"7d\"); ignored if start/end are given."`
	Start            string `json:"start,omitempty" jsonschema:"RFC3339 start timestamp; if omitted along with end and freshness, and the filter expression restricts no timestamp itself, only the last 24 hours are searched. Prefer the moment the event being investigated began, to scope precisely to it."`
	End              string `json:"end,omitempty" jsonschema:"RFC3339 end timestamp; use the moment that event ended, to scope precisely to it."`
}

type logEntrySummary struct {
	Timestamp *string `json:"timestamp"`
	InsertID  *string `json:"insert_id"`
	Severity  *string `json:"severity"`
	LogName   *string `json:"log_name"`
	Payload   any     `json:"payload"`
}

type queryCloudLoggingOutput struct {
	Entries []logEntrySummary `json:"entries"`
}

func (h *handlers) queryCloudLogging(ctx context.Context, in queryCloudLoggingInput) (queryCloudLoggingOutput, error) {
	scope := in.Scope
	if scope == "" {
		scope = h.client.Auth.Project()
	}
	if scope != "" && !strings.Contains(scope, "/") {
		scope = "projects/" + scope
	}
	if strings.TrimSpace(in.FilterExpression) == "" {
		return queryCloudLoggingOutput{}, errors.New(noFilterMessage)
	}
	if strings.TrimSpace(scope) == "" {
		return queryCloudLoggingOutput{}, errors.New(noScopeMessage)
	}

	now := time.Now()
	timeClause, err := gcp.TimeFilter(in.Freshness, in.Start, in.End, now)
	if err != nil {
		return queryCloudLoggingOutput{}, err
	}
	filter := in.FilterExpression
	if timeClause != "" {
		filter += " AND " + timeClause
	}
	entries, err := h.client.LogEntries(ctx, scope, gcp.WithDefaultWindow(filter, now))
	if err != nil {
		return queryCloudLoggingOutput{}, err
	}

	output := queryCloudLoggingOutput{Entries: []logEntrySummary{}}
	for _, entry := range entries {
		output.Entries = append(output.Entries, logEntrySummary{
			Timestamp: entry.Timestamp, InsertID: entry.InsertID, Severity: entry.Severity,
			LogName: entry.LogName, Payload: entry.Payload(),
		})
	}
	return output, nil
}

type getServicePerimeterPolicyInput struct {
	ServicePerimeter string `json:"service_perimeter" jsonschema:"full resource name, e.g. \"accessPolicies/<id>/servicePerimeters/<name>\" -- found in a VPC SC audit log entry's protoPayload.metadata.securityPolicyInfo.servicePerimeterName."`
}

type perimeterConfigSummary struct {
	RestrictedServices                      []string `json:"restricted_services"`
	VPCAccessibleServicesRestrictionEnabled bool     `json:"vpc_accessible_services_restriction_enabled"`
	VPCAccessibleServicesAllowed            []string `json:"vpc_accessible_services_allowed"`
	IngressPolicies                         []any    `json:"ingress_policies"`
	EgressPolicies                          []any    `json:"egress_policies"`
	Resources                               []string `json:"resources"`
}

// summarizePerimeterConfig returns the fields of a perimeter's status or spec that a fix
// advisory needs, or nil when the perimeter has no such configuration.
func summarizePerimeterConfig(config *gcp.ServicePerimeterConfig) *perimeterConfigSummary {
	if config == nil {
		return nil
	}
	summary := &perimeterConfigSummary{
		RestrictedServices: orEmpty(config.RestrictedServices), VPCAccessibleServicesAllowed: []string{},
		IngressPolicies: orEmpty(config.IngressPolicies), EgressPolicies: orEmpty(config.EgressPolicies),
		Resources: orEmpty(config.Resources),
	}
	if config.VPCAccessibleServices != nil {
		summary.VPCAccessibleServicesRestrictionEnabled = config.VPCAccessibleServices.EnableRestriction
		summary.VPCAccessibleServicesAllowed = orEmpty(config.VPCAccessibleServices.AllowedServices)
	}
	return summary
}

type getServicePerimeterPolicyOutput struct {
	Title                 *string                 `json:"title"`
	PerimeterType         string                  `json:"perimeter_type"`
	UseExplicitDryRunSpec bool                    `json:"use_explicit_dry_run_spec"`
	Status                *perimeterConfigSummary `json:"status"`
	Spec                  *perimeterConfigSummary `json:"spec"`
}

func (h *handlers) getServicePerimeterPolicy(ctx context.Context, in getServicePerimeterPolicyInput) (getServicePerimeterPolicyOutput, error) {
	perimeter, err := h.client.ServicePerimeter(ctx, in.ServicePerimeter)
	if err != nil {
		return getServicePerimeterPolicyOutput{}, err
	}
	output := getServicePerimeterPolicyOutput{
		Title: perimeter.Title, PerimeterType: defaultPerimeterType, UseExplicitDryRunSpec: perimeter.UseExplicitDryRunSpec,
		Status: summarizePerimeterConfig(perimeter.Status), Spec: summarizePerimeterConfig(perimeter.Spec),
	}
	if perimeter.PerimeterType != nil {
		output.PerimeterType = *perimeter.PerimeterType
	}
	return output, nil
}

type getAccessLevelInput struct {
	AccessLevel string `json:"access_level" jsonschema:"full resource name, e.g. \"accessPolicies/<id>/accessLevels/<name>\" -- found in a VPC SC audit log entry's metadata.accessLevels, or in a service perimeter's ingress/egress policy sources."`
}

type conditionSummary struct {
	IPSubnetworks []string `json:"ip_subnetworks"`
	Members       []string `json:"members"`
	Regions       []string `json:"regions"`
	Negate        bool     `json:"negate"`
	DevicePolicy  any      `json:"device_policy"`
}

type getAccessLevelOutput struct {
	Title             *string            `json:"title"`
	CombiningFunction string             `json:"combining_function"`
	Conditions        []conditionSummary `json:"conditions"`
}

func (h *handlers) getAccessLevel(ctx context.Context, in getAccessLevelInput) (getAccessLevelOutput, error) {
	level, err := h.client.AccessLevel(ctx, in.AccessLevel)
	if err != nil {
		return getAccessLevelOutput{}, err
	}
	output := getAccessLevelOutput{Title: level.Title, CombiningFunction: defaultCombiningFunction, Conditions: []conditionSummary{}}
	if level.Basic == nil {
		return output, nil
	}
	if level.Basic.CombiningFunction != nil {
		output.CombiningFunction = *level.Basic.CombiningFunction
	}
	for _, condition := range level.Basic.Conditions {
		output.Conditions = append(output.Conditions, conditionSummary{
			IPSubnetworks: orEmpty(condition.IPSubnetworks), Members: orEmpty(condition.Members),
			Regions: orEmpty(condition.Regions), Negate: condition.Negate, DevicePolicy: condition.DevicePolicy,
		})
	}
	return output, nil
}

// resourceArg is the project, folder or organization argument of the IAM tools.
type resourceArg struct {
	Resource string `json:"resource" jsonschema:"GCP project ID, e.g. \"my-project\", or \"folders/<id>\" or \"organizations/<id>\" for a policy higher in the resource hierarchy (gcp_get_project_ancestry lists a project's folders and organization)."`
}

type getIAMPolicyOutput struct {
	Bindings []gcp.Binding `json:"bindings"`
}

func (h *handlers) getIAMPolicy(ctx context.Context, in resourceArg) (getIAMPolicyOutput, error) {
	bindings, err := h.client.IAMBindings(ctx, hierarchyName(in.Resource))
	if err != nil {
		return getIAMPolicyOutput{}, err
	}
	output := getIAMPolicyOutput{Bindings: []gcp.Binding{}}
	for _, binding := range bindings {
		binding.Members = orEmpty(binding.Members)
		output.Bindings = append(output.Bindings, binding)
	}
	return output, nil
}

type getIAMRolesForMemberInput struct {
	resourceArg
	Member string `json:"member" jsonschema:"the IAM member to check, including its type prefix, e.g. \"serviceAccount:sa-name@my-project.iam.gserviceaccount.com\" or \"user:name@example.com\"."`
}

type roleSummary struct {
	Role      *string `json:"role"`
	Condition any     `json:"condition"`
}

type getIAMRolesForMemberOutput struct {
	Roles []roleSummary `json:"roles"`
}

func (h *handlers) getIAMRolesForMember(ctx context.Context, in getIAMRolesForMemberInput) (getIAMRolesForMemberOutput, error) {
	bindings, err := h.client.IAMBindings(ctx, hierarchyName(in.Resource))
	if err != nil {
		return getIAMRolesForMemberOutput{}, err
	}
	output := getIAMRolesForMemberOutput{Roles: []roleSummary{}}
	for _, binding := range bindings {
		if slices.Contains(binding.Members, in.Member) {
			output.Roles = append(output.Roles, roleSummary{Role: binding.Role, Condition: binding.Condition})
		}
	}
	return output, nil
}

type resolveProjectIdentifiersInput struct {
	Project string `json:"project" jsonschema:"one GCP project ID (e.g. \"my-project\") or numeric project number (e.g. \"123456789012\"), or several of either separated by commas."`
}

type projectSummary struct {
	Requested     string  `json:"requested"`
	ProjectID     *string `json:"project_id,omitempty"`
	ProjectNumber *string `json:"project_number,omitempty"`
	DisplayName   *string `json:"display_name,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type resolveProjectIdentifiersOutput struct {
	Projects []projectSummary `json:"projects"`
}

func (h *handlers) resolveProjectIdentifiers(ctx context.Context, in resolveProjectIdentifiersInput) (resolveProjectIdentifiersOutput, error) {
	var names []string
	for name := range strings.SplitSeq(in.Project, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return resolveProjectIdentifiersOutput{}, errors.New(noProjectMessage)
	}

	output := resolveProjectIdentifiersOutput{Projects: []projectSummary{}}
	for _, name := range names {
		project, err := h.client.Project(ctx, name)
		if err != nil {
			output.Projects = append(output.Projects, projectSummary{Requested: name, Error: err.Error()})
			continue
		}
		number := project.ProjectNumber()
		output.Projects = append(output.Projects, projectSummary{
			Requested: name, ProjectID: project.ProjectID, ProjectNumber: &number, DisplayName: project.DisplayName,
		})
	}
	return output, nil
}

type getRoleInput struct {
	Role string `json:"role" jsonschema:"role name as it appears in an IAM binding: \"roles/<name>\" for a predefined role, \"projects/<id>/roles/<name>\" or \"organizations/<id>/roles/<name>\" for a custom role. A bare name is taken as a predefined role and prefixed with \"roles/\"."`
}

type getRoleOutput struct {
	Name                *string  `json:"name"`
	Title               *string  `json:"title"`
	Description         *string  `json:"description"`
	Stage               *string  `json:"stage"`
	Deleted             bool     `json:"deleted"`
	IncludedPermissions []string `json:"included_permissions"`
}

func (h *handlers) getRole(ctx context.Context, in getRoleInput) (getRoleOutput, error) {
	name := strings.TrimSpace(in.Role)
	if !strings.Contains(name, "/") {
		name = "roles/" + name
	}
	role, err := h.client.Role(ctx, name)
	if err != nil {
		return getRoleOutput{}, err
	}
	return getRoleOutput{
		Name: role.Name, Title: role.Title, Description: role.Description, Stage: role.Stage, Deleted: role.Deleted,
		IncludedPermissions: orEmpty(role.IncludedPermissions),
	}, nil
}

type getProjectAncestryInput struct {
	Project string `json:"project" jsonschema:"GCP project ID (e.g. \"my-project\") or project number."`
}

type getProjectAncestryOutput struct {
	Ancestors []gcp.ResourceID `json:"ancestors"`
}

func (h *handlers) getProjectAncestry(ctx context.Context, in getProjectAncestryInput) (getProjectAncestryOutput, error) {
	ancestry, err := h.client.ProjectAncestry(ctx, strings.TrimPrefix(strings.TrimSpace(in.Project), "projects/"))
	if err != nil {
		return getProjectAncestryOutput{}, err
	}
	return getProjectAncestryOutput{Ancestors: ancestry}, nil
}

type troubleshootIAMPermissionInput struct {
	Principal  string `json:"principal" jsonschema:"email of the user or service account to check, e.g. \"sa-name@my-project.iam.gserviceaccount.com\"; a \"user:\" or \"serviceAccount:\" prefix is removed. Groups, domains and workforce or workload identities are not supported."`
	Resource   string `json:"resource" jsonschema:"full resource name the permission is checked on, e.g. \"//storage.googleapis.com/projects/_/buckets/my-bucket\" -- an audit log entry's protoPayload.resourceName is often the part after the service host. A bare project ID is taken as \"//cloudresourcemanager.googleapis.com/projects/<id>\"."`
	Permission string `json:"permission" jsonschema:"the IAM permission, e.g. \"storage.objects.get\" -- found in an audit log entry's protoPayload.authorizationInfo[].permission."`
}

type allowPolicySummary struct {
	FullResourceName *string                       `json:"full_resource_name"`
	AllowAccessState *string                       `json:"allow_access_state"`
	Relevance        *string                       `json:"relevance"`
	Bindings         []gcp.AllowBindingExplanation `json:"bindings"`
}

type troubleshootIAMPermissionOutput struct {
	OverallAccessState    *string              `json:"overall_access_state"`
	AllowAccessState      *string              `json:"allow_access_state"`
	AllowPolicies         []allowPolicySummary `json:"allow_policies"`
	DenyPolicyExplanation any                  `json:"deny_policy_explanation"`
}

func (h *handlers) troubleshootIAMPermission(ctx context.Context, in troubleshootIAMPermissionInput) (troubleshootIAMPermissionOutput, error) {
	resource := strings.TrimSpace(in.Resource)
	if !strings.Contains(resource, "/") {
		resource = "//cloudresourcemanager.googleapis.com/projects/" + resource
	}
	result, err := h.client.TroubleshootIAM(ctx, gcp.AccessTuple{
		Principal: principalEmail(in.Principal), FullResourceName: resource, Permission: strings.TrimSpace(in.Permission),
	})
	if err != nil {
		return troubleshootIAMPermissionOutput{}, err
	}

	output := troubleshootIAMPermissionOutput{
		OverallAccessState: result.OverallAccessState, AllowPolicies: []allowPolicySummary{},
		DenyPolicyExplanation: result.DenyPolicyExplanation,
	}
	if result.AllowPolicyExplanation == nil {
		return output, nil
	}
	output.AllowAccessState = result.AllowPolicyExplanation.AllowAccessState
	for _, policy := range result.AllowPolicyExplanation.ExplainedPolicies {
		summary := allowPolicySummary{
			FullResourceName: policy.FullResourceName, AllowAccessState: policy.AllowAccessState, Relevance: policy.Relevance,
			Bindings: []gcp.AllowBindingExplanation{},
		}
		// Bindings whose role lacks the permission cannot grant it and are left out.
		for _, binding := range policy.BindingExplanations {
			if binding.RolePermission == nil || *binding.RolePermission != "ROLE_PERMISSION_NOT_INCLUDED" {
				summary.Bindings = append(summary.Bindings, binding)
			}
		}
		output.AllowPolicies = append(output.AllowPolicies, summary)
	}
	return output, nil
}

type getServiceAccountInput struct {
	ServiceAccount string `json:"service_account" jsonschema:"the service account's email, or its numeric unique ID as audit logs sometimes give it; a \"serviceAccount:\" prefix is removed. A full \"projects/<id>/serviceAccounts/<email or unique ID>\" name is also accepted."`
}

type getServiceAccountOutput struct {
	Name           string        `json:"name"`
	Email          *string       `json:"email"`
	UniqueID       *string       `json:"unique_id"`
	ProjectID      *string       `json:"project_id"`
	DisplayName    *string       `json:"display_name"`
	Description    *string       `json:"description"`
	OAuth2ClientID *string       `json:"oauth2_client_id"`
	Disabled       bool          `json:"disabled"`
	IAMBindings    []gcp.Binding `json:"iam_bindings"`
	IAMPolicyError string        `json:"iam_policy_error,omitempty"`
}

func (h *handlers) getServiceAccount(ctx context.Context, in getServiceAccountInput) (getServiceAccountOutput, error) {
	name := principalEmail(in.ServiceAccount)
	if !strings.Contains(name, "/") {
		name = "projects/-/serviceAccounts/" + name
	}
	account, err := h.client.ServiceAccount(ctx, name)
	if err != nil {
		return getServiceAccountOutput{}, err
	}
	output := getServiceAccountOutput{
		Name: account.Name, Email: account.Email, UniqueID: account.UniqueID, ProjectID: account.ProjectID,
		DisplayName: account.DisplayName, Description: account.Description, OAuth2ClientID: account.OAuth2ClientID,
		Disabled: account.Disabled, IAMBindings: []gcp.Binding{},
	}
	bindings, err := h.client.ServiceAccountIAMBindings(ctx, account.Name)
	if err != nil {
		output.IAMPolicyError = err.Error()
		return output, nil
	}
	for _, binding := range bindings {
		binding.Members = orEmpty(binding.Members)
		output.IAMBindings = append(output.IAMBindings, binding)
	}
	return output, nil
}

type listAccessPoliciesInput struct {
	Organization string `json:"organization" jsonschema:"organization ID, e.g. \"123456789012\", or \"organizations/<id>\" -- gcp_get_project_ancestry or gcp_list_organizations finds it."`
}

type accessPolicySummary struct {
	Name   string   `json:"name"`
	Title  *string  `json:"title"`
	Parent *string  `json:"parent"`
	Scopes []string `json:"scopes"`
}

type listAccessPoliciesOutput struct {
	AccessPolicies []accessPolicySummary `json:"access_policies"`
}

func (h *handlers) listAccessPolicies(ctx context.Context, in listAccessPoliciesInput) (listAccessPoliciesOutput, error) {
	organization := strings.TrimSpace(in.Organization)
	if !strings.Contains(organization, "/") {
		organization = "organizations/" + organization
	}
	policies, err := h.client.AccessPolicies(ctx, organization)
	if err != nil {
		return listAccessPoliciesOutput{}, err
	}
	output := listAccessPoliciesOutput{AccessPolicies: []accessPolicySummary{}}
	for _, policy := range policies {
		output.AccessPolicies = append(output.AccessPolicies, accessPolicySummary{
			Name: policy.Name, Title: policy.Title, Parent: policy.Parent, Scopes: orEmpty(policy.Scopes),
		})
	}
	return output, nil
}

type listServicePerimetersInput struct {
	AccessPolicy string `json:"access_policy" jsonschema:"access policy ID, e.g. \"123456789\", or \"accessPolicies/<id>\" -- gcp_list_access_policies finds it."`
	Project      string `json:"project,omitempty" jsonschema:"GCP project ID or number; when given, only the perimeters whose enforced or dry-run resources include the project are returned."`
}

type perimeterListing struct {
	Name            string   `json:"name"`
	Title           *string  `json:"title"`
	PerimeterType   string   `json:"perimeter_type"`
	Resources       []string `json:"resources"`
	DryRunResources []string `json:"dry_run_resources"`
}

type listServicePerimetersOutput struct {
	ServicePerimeters []perimeterListing `json:"service_perimeters"`
}

func (h *handlers) listServicePerimeters(ctx context.Context, in listServicePerimetersInput) (listServicePerimetersOutput, error) {
	policy := strings.TrimSpace(in.AccessPolicy)
	if !strings.Contains(policy, "/") {
		policy = "accessPolicies/" + policy
	}

	// Perimeters name their projects by number, so a project ID is resolved to one first.
	var member string
	if project := strings.TrimPrefix(strings.TrimSpace(in.Project), "projects/"); project != "" {
		if strings.Trim(project, "0123456789") != "" {
			info, err := h.client.Project(ctx, project)
			if err != nil {
				return listServicePerimetersOutput{}, err
			}
			project = info.ProjectNumber()
		}
		member = "projects/" + project
	}

	perimeters, err := h.client.ServicePerimeters(ctx, policy)
	if err != nil {
		return listServicePerimetersOutput{}, err
	}
	output := listServicePerimetersOutput{ServicePerimeters: []perimeterListing{}}
	for _, perimeter := range perimeters {
		listing := perimeterListing{
			Name: perimeter.Name, Title: perimeter.Title, PerimeterType: defaultPerimeterType,
			Resources: []string{}, DryRunResources: []string{},
		}
		if perimeter.PerimeterType != nil {
			listing.PerimeterType = *perimeter.PerimeterType
		}
		if perimeter.Status != nil {
			listing.Resources = orEmpty(perimeter.Status.Resources)
		}
		if perimeter.Spec != nil {
			listing.DryRunResources = orEmpty(perimeter.Spec.Resources)
		}
		if member != "" && !slices.Contains(listing.Resources, member) && !slices.Contains(listing.DryRunResources, member) {
			continue
		}
		output.ServicePerimeters = append(output.ServicePerimeters, listing)
	}
	return output, nil
}

type getEffectiveOrgPolicyInput struct {
	Resource   string `json:"resource" jsonschema:"GCP project ID, e.g. \"my-project\", or \"folders/<id>\" or \"organizations/<id>\"."`
	Constraint string `json:"constraint" jsonschema:"the constraint name, e.g. \"iam.allowedPolicyMemberDomains\" or \"gcp.resourceLocations\"; a \"constraints/\" prefix, as error messages give it, is removed."`
}

type getEffectiveOrgPolicyOutput struct {
	Name       string `json:"name"`
	Spec       any    `json:"spec"`
	DryRunSpec any    `json:"dry_run_spec"`
}

func (h *handlers) getEffectiveOrgPolicy(ctx context.Context, in getEffectiveOrgPolicyInput) (getEffectiveOrgPolicyOutput, error) {
	constraint := strings.TrimPrefix(strings.TrimSpace(in.Constraint), "constraints/")
	policy, err := h.client.EffectiveOrgPolicy(ctx, hierarchyName(in.Resource)+"/policies/"+constraint)
	if err != nil {
		return getEffectiveOrgPolicyOutput{}, err
	}
	return getEffectiveOrgPolicyOutput{Name: policy.Name, Spec: policy.Spec, DryRunSpec: policy.DryRunSpec}, nil
}

type searchIAMPoliciesInput struct {
	Scope      string   `json:"scope" jsonschema:"where to search: \"organizations/<id>\", \"folders/<id>\", or a GCP project ID or number."`
	Query      string   `json:"query" jsonschema:"Cloud Asset Inventory IAM policy query, e.g. \"policy:user@example.com\" for one member's bindings, \"policy:roles/storage.admin\" for one role's, or \"policy.role.permissions:storage.buckets.update\" for roles holding one permission."`
	AssetTypes []string `json:"asset_types,omitempty" jsonschema:"asset types the policies are attached to, e.g. [\"cloudresourcemanager.googleapis.com/Project\"] or [\"storage.googleapis.com/Bucket\"]; regular expressions such as \"compute.googleapis.com.*\" are accepted. Omit it to search every type."`
}

type iamPolicySearchSummary struct {
	Resource     *string       `json:"resource"`
	AssetType    *string       `json:"asset_type"`
	Project      *string       `json:"project"`
	Folders      []string      `json:"folders"`
	Organization *string       `json:"organization"`
	Bindings     []gcp.Binding `json:"bindings"`
}

type searchIAMPoliciesOutput struct {
	Results []iamPolicySearchSummary `json:"results"`
}

func (h *handlers) searchIAMPolicies(ctx context.Context, in searchIAMPoliciesInput) (searchIAMPoliciesOutput, error) {
	if strings.TrimSpace(in.Query) == "" {
		return searchIAMPoliciesOutput{}, errors.New(noQueryMessage)
	}
	results, err := h.client.SearchIAMPolicies(ctx, hierarchyName(in.Scope), in.Query, in.AssetTypes)
	if err != nil {
		return searchIAMPoliciesOutput{}, err
	}
	output := searchIAMPoliciesOutput{Results: []iamPolicySearchSummary{}}
	for _, result := range results {
		summary := iamPolicySearchSummary{
			Resource: result.Resource, AssetType: result.AssetType, Project: result.Project,
			Folders: orEmpty(result.Folders), Organization: result.Organization, Bindings: []gcp.Binding{},
		}
		for _, binding := range result.Policy.Bindings {
			binding.Members = orEmpty(binding.Members)
			summary.Bindings = append(summary.Bindings, binding)
		}
		output.Results = append(output.Results, summary)
	}
	return output, nil
}

type listOrganizationsInput struct {
	Query string `json:"query,omitempty" jsonschema:"filter, e.g. \"domain:example.com\" or \"directorycustomerid:123456789\"; omit it to list every organization the identity can see."`
}

type organizationSummary struct {
	Name                string  `json:"name"`
	DisplayName         *string `json:"display_name"`
	DirectoryCustomerID *string `json:"directory_customer_id"`
	State               *string `json:"state"`
}

type listOrganizationsOutput struct {
	Organizations []organizationSummary `json:"organizations"`
}

func (h *handlers) listOrganizations(ctx context.Context, in listOrganizationsInput) (listOrganizationsOutput, error) {
	organizations, err := h.client.Organizations(ctx, strings.TrimSpace(in.Query))
	if err != nil {
		return listOrganizationsOutput{}, err
	}
	output := listOrganizationsOutput{Organizations: []organizationSummary{}}
	for _, organization := range organizations {
		output.Organizations = append(output.Organizations, organizationSummary{
			Name: organization.Name, DisplayName: organization.DisplayName,
			DirectoryCustomerID: organization.DirectoryCustomerID, State: organization.State,
		})
	}
	return output, nil
}

type listFoldersInput struct {
	Parent string `json:"parent,omitempty" jsonschema:"\"organizations/<id>\" or \"folders/<id>\" to list that resource's direct child folders; excludes query."`
	Query  string `json:"query,omitempty" jsonschema:"search across every folder the identity can see, e.g. \"displayName=Prod*\" or \"parent=folders/123 AND state=ACTIVE\"; excludes parent. Omit both to list every visible folder."`
}

type folderSummary struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"display_name"`
	Parent      *string `json:"parent"`
	State       *string `json:"state"`
}

type listFoldersOutput struct {
	Folders []folderSummary `json:"folders"`
}

func (h *handlers) listFolders(ctx context.Context, in listFoldersInput) (listFoldersOutput, error) {
	parent, query := strings.TrimSpace(in.Parent), strings.TrimSpace(in.Query)
	if parent != "" && query != "" {
		return listFoldersOutput{}, errors.New(parentAndQueryMessage)
	}
	folders, err := h.client.Folders(ctx, parent, query)
	if err != nil {
		return listFoldersOutput{}, err
	}
	output := listFoldersOutput{Folders: []folderSummary{}}
	for _, folder := range folders {
		output.Folders = append(output.Folders, folderSummary{
			Name: folder.Name, DisplayName: folder.DisplayName, Parent: folder.Parent, State: folder.State,
		})
	}
	return output, nil
}

type listProjectsInput struct {
	Parent string `json:"parent,omitempty" jsonschema:"\"organizations/<id>\" or \"folders/<id>\" to list that resource's direct child projects; excludes query."`
	Query  string `json:"query,omitempty" jsonschema:"search across every project the identity can see, e.g. \"name:prod*\" or \"labels.env:prod\"; excludes parent. Omit both to list every visible project."`
}

type projectListing struct {
	ProjectID     *string           `json:"project_id"`
	ProjectNumber string            `json:"project_number"`
	DisplayName   *string           `json:"display_name"`
	Parent        *string           `json:"parent"`
	State         *string           `json:"state"`
	Labels        map[string]string `json:"labels"`
}

type listProjectsOutput struct {
	Projects []projectListing `json:"projects"`
}

func (h *handlers) listProjects(ctx context.Context, in listProjectsInput) (listProjectsOutput, error) {
	parent, query := strings.TrimSpace(in.Parent), strings.TrimSpace(in.Query)
	if parent != "" && query != "" {
		return listProjectsOutput{}, errors.New(parentAndQueryMessage)
	}
	projects, err := h.client.Projects(ctx, parent, query)
	if err != nil {
		return listProjectsOutput{}, err
	}
	output := listProjectsOutput{Projects: []projectListing{}}
	for _, project := range projects {
		labels := project.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		output.Projects = append(output.Projects, projectListing{
			ProjectID: project.ProjectID, ProjectNumber: project.ProjectNumber(), DisplayName: project.DisplayName,
			Parent: project.Parent, State: project.State, Labels: labels,
		})
	}
	return output, nil
}
