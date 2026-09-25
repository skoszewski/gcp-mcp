package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scope is the OAuth scope the Application Default Credentials' access tokens are issued for.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

const quotaProjectHeader = "X-Goog-User-Project"

// Authentication method names accepted by NewAuthorizer.
const (
	AuthADC  = "adc"
	AuthNone = "none"
)

// Authorizer authenticates Google Cloud REST requests.
type Authorizer interface {
	// Authorize sets the Authorization header, and the quota project header when one is
	// configured, on request.
	Authorize(ctx context.Context, request *http.Request) error
	// Method describes the authentication method, for the startup banner.
	Method() string
	// Project returns the project a tool call applies to when it names none, or "".
	Project() string
}

// NewAuthorizer returns the Authorizer for method, reading its settings through getenv.
//
// AuthADC uses the Application Default Credentials: GOOGLE_APPLICATION_CREDENTIALS, the gcloud
// well-known file, or the metadata server. AuthNone configures no credential, so every request
// needs one from WithAuthorization.
//
// The default project is GOOGLE_CLOUD_PROJECT, then GCLOUD_PROJECT, then, under AuthADC, the
// credentials' own project, and for user credentials the project configured in the Google Cloud
// CLI. The quota project is GOOGLE_CLOUD_QUOTA_PROJECT, then, under AuthADC, the credentials'
// quota_project_id.
func NewAuthorizer(ctx context.Context, method string, getenv func(string) string) (Authorizer, error) {
	project := getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		project = getenv("GCLOUD_PROJECT")
	}
	quotaProject := getenv("GOOGLE_CLOUD_QUOTA_PROJECT")

	switch method {
	case AuthADC:
		credentials, err := google.FindDefaultCredentials(ctx, Scope)
		if err != nil {
			return nil, fmt.Errorf("could not find the Application Default Credentials: %w", err)
		}
		var file struct {
			Type           string `json:"type"`
			QuotaProjectID string `json:"quota_project_id"`
		}
		credentialType := "metadata server"
		if credentials.JSON != nil {
			if err := json.Unmarshal(credentials.JSON, &file); err != nil {
				return nil, fmt.Errorf("could not read the Application Default Credentials: %w", err)
			}
			credentialType = file.Type
		}
		if quotaProject == "" {
			quotaProject = file.QuotaProjectID
		}
		if project == "" {
			project = credentials.ProjectID
		}
		if project == "" && file.Type == "authorized_user" {
			project = gcloudProject(ctx)
		}
		return &adcAuthorizer{
			method:       fmt.Sprintf("Application Default Credentials (%s)", credentialType),
			tokenSource:  credentials.TokenSource,
			project:      project,
			quotaProject: quotaProject,
		}, nil
	case AuthNone:
		return noneAuthorizer{project: project}, nil
	}
	return nil, fmt.Errorf("unknown authentication method %q; use %s or %s", method, AuthADC, AuthNone)
}

// gcloudProject returns the project configured in the Google Cloud CLI, or "" when the CLI is
// not installed or has no project set.
func gcloudProject(ctx context.Context) string {
	output, err := exec.CommandContext(ctx, "gcloud", "config", "get-value", "project").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// adcAuthorizer authenticates with an access token from the Application Default Credentials,
// which the token source caches until shortly before it expires.
type adcAuthorizer struct {
	method       string
	tokenSource  oauth2.TokenSource
	project      string
	quotaProject string
}

func (a *adcAuthorizer) Authorize(_ context.Context, request *http.Request) error {
	token, err := a.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("could not get a Google Cloud access token with %s: %w", a.method, err)
	}
	token.SetAuthHeader(request)
	if a.quotaProject != "" {
		request.Header.Set(quotaProjectHeader, a.quotaProject)
	}
	return nil
}

func (a *adcAuthorizer) Method() string {
	return a.method
}

func (a *adcAuthorizer) Project() string {
	return a.project
}

// noneAuthorizer holds no credential; a request succeeds only with one from WithAuthorization.
type noneAuthorizer struct {
	project string
}

func (noneAuthorizer) Authorize(context.Context, *http.Request) error {
	return errors.New("no credential: the server is configured with --auth none, so the MCP client must send an Authorization header")
}

func (noneAuthorizer) Method() string {
	return "none (the MCP client sends an Authorization header)"
}

func (a noneAuthorizer) Project() string {
	return a.project
}

type authorizationKey struct{}

// WithAuthorization returns a context whose requests send value as their Authorization header
// instead of authenticating with the client's Authorizer.
func WithAuthorization(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, authorizationKey{}, value)
}

// RequestAuthorization returns the Authorization header value WithAuthorization stored in ctx,
// or "".
func RequestAuthorization(ctx context.Context) string {
	value, _ := ctx.Value(authorizationKey{}).(string)
	return value
}
