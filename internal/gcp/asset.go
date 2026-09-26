package gcp

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
)

// IAMPolicySearchPageSize is the number of results each searchAllIamPolicies request asks for,
// the most the method returns.
const IAMPolicySearchPageSize = 500

var assetScopeRE = regexp.MustCompile(`^[^/]+/[^/]+$`)

// IAMPolicySearchResult is one IAM policy found by Cloud Asset Inventory, holding only the
// bindings that match the query.
type IAMPolicySearchResult struct {
	Resource     *string  `json:"resource"`
	AssetType    *string  `json:"assetType"`
	Project      *string  `json:"project"`
	Folders      []string `json:"folders"`
	Organization *string  `json:"organization"`
	Policy       struct {
		Bindings []Binding `json:"bindings"`
	} `json:"policy"`
}

// SearchIAMPolicies returns every IAM policy within scope, projects/<id>, folders/<id> or
// organizations/<id>, with bindings matching query, attached to one of assetTypes or to any
// asset type when it is empty.
func (c *Client) SearchIAMPolicies(ctx context.Context, scope, query string, assetTypes []string) ([]IAMPolicySearchResult, error) {
	if err := validateName("scope", scope, assetScopeRE); err != nil {
		return nil, err
	}
	params := url.Values{"query": {query}, "pageSize": {strconv.Itoa(IAMPolicySearchPageSize)}, "assetTypes": assetTypes}
	return listAll[IAMPolicySearchResult](ctx, c, cloudAssetURL+"/"+escapeName(scope)+":searchAllIamPolicies", params, "results")
}
