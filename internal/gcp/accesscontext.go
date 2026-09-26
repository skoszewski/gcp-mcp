package gcp

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
)

var (
	accessPolicyNameRE     = regexp.MustCompile(`^accessPolicies/[^/]+$`)
	organizationNameRE     = regexp.MustCompile(`^organizations/[^/]+$`)
	servicePerimeterNameRE = regexp.MustCompile(`^accessPolicies/[^/]+/servicePerimeters/[^/]+$`)
	accessLevelNameRE      = regexp.MustCompile(`^accessPolicies/[^/]+/accessLevels/[^/]+$`)
)

// AccessPolicy is a VPC Service Controls access policy.
type AccessPolicy struct {
	Name   string   `json:"name"`
	Title  *string  `json:"title"`
	Parent *string  `json:"parent"`
	Scopes []string `json:"scopes"`
}

// ServicePerimeter is a VPC Service Controls perimeter.
type ServicePerimeter struct {
	Name                  string                  `json:"name"`
	Title                 *string                 `json:"title"`
	PerimeterType         *string                 `json:"perimeterType"`
	UseExplicitDryRunSpec bool                    `json:"useExplicitDryRunSpec"`
	Status                *ServicePerimeterConfig `json:"status"`
	Spec                  *ServicePerimeterConfig `json:"spec"`
}

// ServicePerimeterConfig is the enforced (status) or dry-run (spec) configuration of a perimeter.
type ServicePerimeterConfig struct {
	RestrictedServices    []string `json:"restrictedServices"`
	VPCAccessibleServices *struct {
		EnableRestriction bool     `json:"enableRestriction"`
		AllowedServices   []string `json:"allowedServices"`
	} `json:"vpcAccessibleServices"`
	IngressPolicies []any    `json:"ingressPolicies"`
	EgressPolicies  []any    `json:"egressPolicies"`
	Resources       []string `json:"resources"`
}

// AccessLevel is a VPC Service Controls access level.
type AccessLevel struct {
	Title *string `json:"title"`
	Basic *struct {
		CombiningFunction *string          `json:"combiningFunction"`
		Conditions        []LevelCondition `json:"conditions"`
	} `json:"basic"`
}

// LevelCondition is one condition of a basic access level.
type LevelCondition struct {
	IPSubnetworks []string `json:"ipSubnetworks"`
	Members       []string `json:"members"`
	Regions       []string `json:"regions"`
	Negate        bool     `json:"negate"`
	DevicePolicy  any      `json:"devicePolicy"`
}

// AccessPolicies returns the access policies of the organization named organizations/<id>.
func (c *Client) AccessPolicies(ctx context.Context, organization string) ([]AccessPolicy, error) {
	if err := validateName("parent", organization, organizationNameRE); err != nil {
		return nil, err
	}
	return listAll[AccessPolicy](ctx, c, accessContextManagerURL+"/accessPolicies", url.Values{"parent": {organization}}, "accessPolicies")
}

// ServicePerimeters returns the perimeters of the access policy named accessPolicies/<id>.
func (c *Client) ServicePerimeters(ctx context.Context, policy string) ([]ServicePerimeter, error) {
	if err := validateName("parent", policy, accessPolicyNameRE); err != nil {
		return nil, err
	}
	return listAll[ServicePerimeter](ctx, c, accessContextManagerURL+"/"+escapeName(policy)+"/servicePerimeters", nil, "servicePerimeters")
}

// ServicePerimeter returns the perimeter with the full resource name
// accessPolicies/<id>/servicePerimeters/<name>.
func (c *Client) ServicePerimeter(ctx context.Context, name string) (ServicePerimeter, error) {
	var perimeter ServicePerimeter
	if err := validateName("name", name, servicePerimeterNameRE); err != nil {
		return perimeter, err
	}
	err := c.do(ctx, http.MethodGet, accessContextManagerURL+"/"+escapeName(name), nil, &perimeter)
	return perimeter, err
}

// AccessLevel returns the access level with the full resource name
// accessPolicies/<id>/accessLevels/<name>.
func (c *Client) AccessLevel(ctx context.Context, name string) (AccessLevel, error) {
	var level AccessLevel
	if err := validateName("name", name, accessLevelNameRE); err != nil {
		return level, err
	}
	err := c.do(ctx, http.MethodGet, accessContextManagerURL+"/"+escapeName(name), nil, &level)
	return level, err
}
