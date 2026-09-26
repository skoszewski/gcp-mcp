package gcp

import (
	"context"
	"net/http"
	"regexp"
)

var (
	roleNameRE           = regexp.MustCompile(`^(roles|projects/[^/]+/roles|organizations/[^/]+/roles)/[^/]+$`)
	serviceAccountNameRE = regexp.MustCompile(`^projects/[^/]+/serviceAccounts/[^/]+$`)
)

// Role is a predefined or custom IAM role.
type Role struct {
	Name                *string  `json:"name"`
	Title               *string  `json:"title"`
	Description         *string  `json:"description"`
	Stage               *string  `json:"stage"`
	Deleted             bool     `json:"deleted"`
	IncludedPermissions []string `json:"includedPermissions"`
}

// ServiceAccount is an IAM service account.
type ServiceAccount struct {
	Name           string  `json:"name"`
	ProjectID      *string `json:"projectId"`
	UniqueID       *string `json:"uniqueId"`
	Email          *string `json:"email"`
	DisplayName    *string `json:"displayName"`
	Description    *string `json:"description"`
	OAuth2ClientID *string `json:"oauth2ClientId"`
	Disabled       bool    `json:"disabled"`
}

// AccessTuple is the principal, full resource name and permission Policy Troubleshooter checks.
type AccessTuple struct {
	Principal        string `json:"principal"`
	FullResourceName string `json:"fullResourceName"`
	Permission       string `json:"permission"`
}

// Troubleshooting is Policy Troubleshooter's verdict on an access tuple, with the explanations
// of the allow and deny policies it evaluated.
type Troubleshooting struct {
	OverallAccessState     *string `json:"overallAccessState"`
	AllowPolicyExplanation *struct {
		AllowAccessState  *string                `json:"allowAccessState"`
		ExplainedPolicies []ExplainedAllowPolicy `json:"explainedPolicies"`
	} `json:"allowPolicyExplanation"`
	DenyPolicyExplanation any `json:"denyPolicyExplanation"`
}

// ExplainedAllowPolicy is how one allow policy contributes to a troubleshooting verdict.
type ExplainedAllowPolicy struct {
	FullResourceName    *string                   `json:"fullResourceName"`
	AllowAccessState    *string                   `json:"allowAccessState"`
	Relevance           *string                   `json:"relevance"`
	BindingExplanations []AllowBindingExplanation `json:"bindingExplanations"`
}

// AllowBindingExplanation is how one role binding of an allow policy contributes to a
// troubleshooting verdict.
type AllowBindingExplanation struct {
	Role                 *string `json:"role"`
	AllowAccessState     *string `json:"allowAccessState"`
	RolePermission       *string `json:"rolePermission"`
	Relevance            *string `json:"relevance"`
	Condition            any     `json:"condition"`
	ConditionExplanation any     `json:"conditionExplanation"`
	CombinedMembership   any     `json:"combinedMembership"`
	Memberships          any     `json:"memberships"`
}

// Role returns the role named roles/<name>, projects/<id>/roles/<name> or
// organizations/<id>/roles/<name>.
func (c *Client) Role(ctx context.Context, name string) (Role, error) {
	var role Role
	if err := validateName("name", name, roleNameRE); err != nil {
		return role, err
	}
	err := c.do(ctx, http.MethodGet, iamURL+"/"+escapeName(name), nil, &role)
	return role, err
}

// ServiceAccount returns the service account named projects/<id>/serviceAccounts/<email or
// unique ID>, where the project may be the wildcard -.
func (c *Client) ServiceAccount(ctx context.Context, name string) (ServiceAccount, error) {
	var account ServiceAccount
	if err := validateName("name", name, serviceAccountNameRE); err != nil {
		return account, err
	}
	err := c.do(ctx, http.MethodGet, iamURL+"/"+escapeName(name), nil, &account)
	return account, err
}

// ServiceAccountIAMBindings returns the bindings of the IAM policy attached to the service
// account named projects/<id>/serviceAccounts/<email or unique ID>.
func (c *Client) ServiceAccountIAMBindings(ctx context.Context, name string) ([]Binding, error) {
	if err := validateName("resource", name, serviceAccountNameRE); err != nil {
		return nil, err
	}
	var policy struct {
		Bindings []Binding `json:"bindings"`
	}
	requestURL := iamURL + "/" + escapeName(name) + ":getIamPolicy?options.requestedPolicyVersion=3"
	err := c.do(ctx, http.MethodPost, requestURL, nil, &policy)
	return policy.Bindings, err
}

// TroubleshootIAM asks Policy Troubleshooter whether a principal has a permission on a resource.
func (c *Client) TroubleshootIAM(ctx context.Context, tuple AccessTuple) (Troubleshooting, error) {
	var result Troubleshooting
	body := map[string]any{"accessTuple": tuple}
	err := c.do(ctx, http.MethodPost, policyTroubleshooterURL+"/iam:troubleshoot", body, &result)
	return result, err
}
