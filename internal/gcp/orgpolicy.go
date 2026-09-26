package gcp

import (
	"context"
	"net/http"
	"regexp"
)

var orgPolicyNameRE = regexp.MustCompile(`^(projects|folders|organizations)/[^/]+/policies/[^/]+$`)

// OrgPolicy is an organization policy: the enforced and dry-run specifications of one constraint.
type OrgPolicy struct {
	Name       string `json:"name"`
	Spec       any    `json:"spec"`
	DryRunSpec any    `json:"dryRunSpec"`
}

// EffectiveOrgPolicy returns the policy in effect for the policy named
// <projects|folders|organizations>/<id>/policies/<constraint>, merged from the resource
// hierarchy.
func (c *Client) EffectiveOrgPolicy(ctx context.Context, name string) (OrgPolicy, error) {
	var policy OrgPolicy
	if err := validateName("name", name, orgPolicyNameRE); err != nil {
		return policy, err
	}
	err := c.do(ctx, http.MethodGet, orgPolicyURL+"/"+escapeName(name)+":getEffectivePolicy", nil, &policy)
	return policy, err
}
