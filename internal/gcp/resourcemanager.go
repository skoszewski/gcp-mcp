package gcp

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// bindingsTTL is how long a project's IAM bindings are reused before they are fetched again.
const bindingsTTL = 5 * time.Minute

var projectNameRE = regexp.MustCompile(`^projects/[^/]+$`)

// Binding is one IAM policy binding: a role, its members and an optional condition.
type Binding struct {
	Role      *string  `json:"role"`
	Members   []string `json:"members"`
	Condition any      `json:"condition"`
}

// Project is a Resource Manager project.
type Project struct {
	Name        string  `json:"name"`
	ProjectID   *string `json:"projectId"`
	DisplayName *string `json:"displayName"`
}

// bindingsKey identifies cached bindings by project and by the Authorization header the request
// carried, so a credential never reads bindings fetched with another.
type bindingsKey struct {
	authorization string
	resource      string
}

type cachedBindings struct {
	bindings []Binding
	fetched  time.Time
}

// ProjectIAMBindings returns the bindings of a project's IAM policy, reusing the ones fetched
// for the same project and credential in the last five minutes.
func (c *Client) ProjectIAMBindings(ctx context.Context, resource string) ([]Binding, error) {
	key := bindingsKey{authorization: RequestAuthorization(ctx), resource: resource}
	c.bindingsMu.Lock()
	cached, found := c.bindings[key]
	c.bindingsMu.Unlock()
	if found && time.Since(cached.fetched) < bindingsTTL {
		return cached.bindings, nil
	}

	body := map[string]any{"options": map[string]any{"requestedPolicyVersion": 3}}
	var policy struct {
		Bindings []Binding `json:"bindings"`
	}
	requestURL := resourceManagerV1URL + "/projects/" + url.PathEscape(resource) + ":getIamPolicy"
	if err := c.do(ctx, http.MethodPost, requestURL, body, &policy); err != nil {
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
