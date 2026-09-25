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
	}
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

// resourceArg is the project argument of the IAM tools.
type resourceArg struct {
	Resource string `json:"resource" jsonschema:"GCP project ID, e.g. \"my-project\" (project-level IAM policy only)."`
}

type getIAMPolicyOutput struct {
	Bindings []gcp.Binding `json:"bindings"`
}

func (h *handlers) getIAMPolicy(ctx context.Context, in resourceArg) (getIAMPolicyOutput, error) {
	bindings, err := h.client.ProjectIAMBindings(ctx, in.Resource)
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
	bindings, err := h.client.ProjectIAMBindings(ctx, in.Resource)
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
