package gcp

import (
	"context"
	"net/http"
	"regexp"
)

var (
	servicePerimeterNameRE = regexp.MustCompile(`^accessPolicies/[^/]+/servicePerimeters/[^/]+$`)
	accessLevelNameRE      = regexp.MustCompile(`^accessPolicies/[^/]+/accessLevels/[^/]+$`)
)

// ServicePerimeter is a VPC Service Controls perimeter.
type ServicePerimeter struct {
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
