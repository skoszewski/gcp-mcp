package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scope is the OAuth scope the Application Default Credentials' access tokens are issued for.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

const quotaProjectHeader = "X-Goog-User-Project"

// wellKnownFile is the file gcloud auth application-default login writes to the Google Cloud CLI
// configuration directory.
const wellKnownFile = "application_default_credentials.json"

// Authentication method names accepted by NewAuthorizer.
const (
	AuthAuto        = "auto"
	AuthAccessToken = "access-token"
	AuthADC         = "adc"
	AuthNone        = "none"
)

// Environment variables the Google Cloud CLI reads an access token from, in order of precedence.
const (
	accessTokenEnv     = "CLOUDSDK_AUTH_ACCESS_TOKEN"
	accessTokenFileEnv = "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"
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
// AuthAuto uses an access token when CLOUDSDK_AUTH_ACCESS_TOKEN or
// CLOUDSDK_AUTH_ACCESS_TOKEN_FILE is set, as the Google Cloud CLI does, otherwise the Application
// Default Credentials. AuthAccessToken and AuthADC force one of the two, and AuthAccessToken fails
// when neither variable is set. AuthNone configures no credential, so every request needs one
// from WithAuthorization.
//
// The default project is GOOGLE_CLOUD_PROJECT, then GCLOUD_PROJECT, then, under AuthADC, the
// credentials' own project, and for an access token or user credentials the project configured
// in the Google Cloud CLI. The quota project is GOOGLE_CLOUD_QUOTA_PROJECT, then, under AuthADC,
// the credentials' quota_project_id.
func NewAuthorizer(ctx context.Context, method string, getenv func(string) string) (Authorizer, error) {
	project := getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		project = getenv("GCLOUD_PROJECT")
	}
	quotaProject := getenv("GOOGLE_CLOUD_QUOTA_PROJECT")
	accessToken, accessTokenFile := getenv(accessTokenEnv), getenv(accessTokenFileEnv)
	accessTokenSet := accessToken != "" || accessTokenFile != ""

	switch method {
	case AuthAuto:
		if accessTokenSet {
			return newAccessTokenAuthorizer(ctx, accessToken, accessTokenFile, project, quotaProject), nil
		}
		return newADCAuthorizer(ctx, getenv, project, quotaProject)
	case AuthAccessToken:
		if !accessTokenSet {
			return nil, fmt.Errorf("--auth %s needs %s or %s", AuthAccessToken, accessTokenEnv, accessTokenFileEnv)
		}
		return newAccessTokenAuthorizer(ctx, accessToken, accessTokenFile, project, quotaProject), nil
	case AuthADC:
		return newADCAuthorizer(ctx, getenv, project, quotaProject)
	case AuthNone:
		return noneAuthorizer{project: project}, nil
	}
	return nil, fmt.Errorf("unknown authentication method %q; use %s, %s, %s or %s",
		method, AuthAuto, AuthAccessToken, AuthADC, AuthNone)
}

// newAccessTokenAuthorizer returns an Authorizer sending accessToken, or when it is empty the
// content of accessTokenFile, read again for every request.
func newAccessTokenAuthorizer(ctx context.Context, accessToken, accessTokenFile, project, quotaProject string) Authorizer {
	method := fmt.Sprintf("access token (%s)", accessTokenEnv)
	if accessToken == "" {
		method = fmt.Sprintf("access token file %s (%s)", accessTokenFile, accessTokenFileEnv)
	}
	if project == "" {
		project = gcloudProject(ctx)
	}
	return &accessTokenAuthorizer{
		method: method, token: strings.TrimSpace(accessToken), file: accessTokenFile,
		project: project, quotaProject: quotaProject,
	}
}

func newADCAuthorizer(ctx context.Context, getenv func(string) string, project, quotaProject string) (Authorizer, error) {
	credentials, err := findDefaultCredentials(ctx, getenv)
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
}

// findDefaultCredentials returns the Application Default Credentials, the first found of:
// GOOGLE_APPLICATION_CREDENTIALS, the application_default_credentials.json file in the Google
// Cloud CLI configuration directory, or the metadata server. The configuration directory is
// CLOUDSDK_CONFIG when it is set, otherwise the Google Cloud CLI default.
func findDefaultCredentials(ctx context.Context, getenv func(string) string) (*google.Credentials, error) {
	configDir := getenv("CLOUDSDK_CONFIG")
	if getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" || configDir == "" {
		return google.FindDefaultCredentials(ctx, Scope)
	}

	path := filepath.Join(configDir, wellKnownFile)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var file struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("%s is not a credentials file: %w", path, err)
		}
		return google.CredentialsFromJSONWithTypeAndParams(ctx, data, google.CredentialsType(file.Type),
			google.CredentialsParams{Scopes: []string{Scope}})
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	case metadata.OnGCE():
		project, _ := metadata.ProjectID()
		return &google.Credentials{ProjectID: project, TokenSource: google.ComputeTokenSource("", Scope)}, nil
	}
	return nil, fmt.Errorf("neither GOOGLE_APPLICATION_CREDENTIALS nor %s names a credentials file, and the metadata server is not available", path)
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

// accessTokenAuthorizer authenticates with an access token given by value or in a file. The
// token is not refreshed; a file is read again for every request, so replacing its content
// replaces the token.
type accessTokenAuthorizer struct {
	method       string
	token        string
	file         string
	project      string
	quotaProject string
}

func (a *accessTokenAuthorizer) Authorize(_ context.Context, request *http.Request) error {
	token := a.token
	if token == "" {
		content, err := os.ReadFile(a.file)
		if err != nil {
			return fmt.Errorf("could not read the access token file named by %s: %w", accessTokenFileEnv, err)
		}
		token = strings.TrimSpace(string(content))
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if a.quotaProject != "" {
		request.Header.Set(quotaProjectHeader, a.quotaProject)
	}
	return nil
}

func (a *accessTokenAuthorizer) Method() string {
	return a.method
}

func (a *accessTokenAuthorizer) Project() string {
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
