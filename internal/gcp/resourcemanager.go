package gcp

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// bindingsTTL is how long a resource's IAM bindings are reused before they are fetched again.
const bindingsTTL = 5 * time.Minute

var (
	projectNameRE   = regexp.MustCompile(`^projects/[^/]+$`)
	hierarchyNameRE = regexp.MustCompile(`^(projects|folders|organizations)/[^/]+$`)
	parentNameRE    = regexp.MustCompile(`^(folders|organizations)/[^/]+$`)
)

// Binding is one IAM policy binding: a role, its members and an optional condition.
type Binding struct {
	Role      *string  `json:"role"`
	Members   []string `json:"members"`
	Condition any      `json:"condition"`
}

// Project is a Resource Manager project.
type Project struct {
	Name        string            `json:"name"`
	ProjectID   *string           `json:"projectId"`
	DisplayName *string           `json:"displayName"`
	Parent      *string           `json:"parent"`
	State       *string           `json:"state"`
	Labels      map[string]string `json:"labels"`
}

// Folder is a Resource Manager folder.
type Folder struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"displayName"`
	Parent      *string `json:"parent"`
	State       *string `json:"state"`
}

// Organization is a Resource Manager organization.
type Organization struct {
	Name                string  `json:"name"`
	DisplayName         *string `json:"displayName"`
	DirectoryCustomerID *string `json:"directoryCustomerId"`
	State               *string `json:"state"`
}

// ResourceID identifies one resource of a project's ancestry by its type and ID.
type ResourceID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// bindingsKey identifies cached bindings by resource and by the Authorization header the request
// carried, so a credential never reads bindings fetched with another.
type bindingsKey struct {
	authorization string
	resource      string
}

type cachedBindings struct {
	bindings []Binding
	fetched  time.Time
}

// IAMBindings returns the bindings of the IAM policy of a project, folder or organization named
// projects/<id>, folders/<id> or organizations/<id>, reusing the ones fetched for the same
// resource and credential in the last five minutes.
func (c *Client) IAMBindings(ctx context.Context, resource string) ([]Binding, error) {
	if err := validateName("resource", resource, hierarchyNameRE); err != nil {
		return nil, err
	}
	key := bindingsKey{authorization: RequestAuthorization(ctx), resource: resource}
	c.bindingsMu.Lock()
	cached, found := c.bindings[key]
	c.bindingsMu.Unlock()
	if found && time.Since(cached.fetched) < bindingsTTL {
		return cached.bindings, nil
	}

	baseURL := resourceManagerV3URL
	if projectNameRE.MatchString(resource) {
		baseURL = resourceManagerV1URL
	}
	body := map[string]any{"options": map[string]any{"requestedPolicyVersion": 3}}
	var policy struct {
		Bindings []Binding `json:"bindings"`
	}
	if err := c.do(ctx, http.MethodPost, baseURL+"/"+escapeName(resource)+":getIamPolicy", body, &policy); err != nil {
		return nil, err
	}

	c.bindingsMu.Lock()
	defer c.bindingsMu.Unlock()
	if c.bindings == nil {
		c.bindings = map[bindingsKey]cachedBindings{}
	}
	c.bindings[key] = cachedBindings{bindings: policy.Bindings, fetched: time.Now()}
	return policy.Bindings, nil
}

// Project returns the project with the given project ID or project number.
func (c *Client) Project(ctx context.Context, project string) (Project, error) {
	var info Project
	name := "projects/" + project
	if err := validateName("name", name, projectNameRE); err != nil {
		return info, err
	}
	err := c.do(ctx, http.MethodGet, resourceManagerV3URL+"/"+escapeName(name), nil, &info)
	return info, err
}

// ProjectNumber returns the project number of a project, taken from its projects/<number> name.
func (p Project) ProjectNumber() string {
	return strings.TrimPrefix(p.Name, "projects/")
}

// ProjectAncestry returns the project with the given project ID or number followed by the
// folders and organization above it, nearest first.
func (c *Client) ProjectAncestry(ctx context.Context, project string) ([]ResourceID, error) {
	if err := validateName("projectId", "projects/"+project, projectNameRE); err != nil {
		return nil, err
	}
	var response struct {
		Ancestor []struct {
			ResourceID ResourceID `json:"resourceId"`
		} `json:"ancestor"`
	}
	requestURL := resourceManagerV1URL + "/projects/" + url.PathEscape(project) + ":getAncestry"
	if err := c.do(ctx, http.MethodPost, requestURL, map[string]any{}, &response); err != nil {
		return nil, err
	}
	ancestry := []ResourceID{}
	for _, ancestor := range response.Ancestor {
		ancestry = append(ancestry, ancestor.ResourceID)
	}
	return ancestry, nil
}

// Organizations returns the organizations the credential can see that match query, or all of
// them when query is empty.
func (c *Client) Organizations(ctx context.Context, query string) ([]Organization, error) {
	params := url.Values{}
	if query != "" {
		params.Set("query", query)
	}
	return listAll[Organization](ctx, c, resourceManagerV3URL+"/organizations:search", params, "organizations")
}

// Folders returns the direct children of parent, folders/<id> or organizations/<id>, when it is
// set, and otherwise the folders the credential can see that match query, or all of them when
// query is empty.
func (c *Client) Folders(ctx context.Context, parent, query string) ([]Folder, error) {
	return listChildren[Folder](ctx, c, "/folders", parent, query, "folders")
}

// Projects returns the direct children of parent, folders/<id> or organizations/<id>, when it is
// set, and otherwise the projects the credential can see that match query, or all of them when
// query is empty.
func (c *Client) Projects(ctx context.Context, parent, query string) ([]Project, error) {
	return listChildren[Project](ctx, c, "/projects", parent, query, "projects")
}

// listChildren lists the Resource Manager v3 collection at path under parent when it is set, and
// otherwise searches it with query.
func listChildren[T any](ctx context.Context, c *Client, path, parent, query, field string) ([]T, error) {
	params := url.Values{}
	if parent != "" {
		if err := validateName("parent", parent, parentNameRE); err != nil {
			return nil, err
		}
		params.Set("parent", parent)
		return listAll[T](ctx, c, resourceManagerV3URL+path, params, field)
	}
	if query != "" {
		params.Set("query", query)
	}
	return listAll[T](ctx, c, resourceManagerV3URL+path+":search", params, field)
}
