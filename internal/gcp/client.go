// Package gcp reads Google Cloud audit logs, VPC Service Controls policies, project IAM
// policies and project identifiers over their REST APIs.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// REST API base URLs.
const (
	loggingURL              = "https://logging.googleapis.com/v2"
	resourceManagerV1URL    = "https://cloudresourcemanager.googleapis.com/v1"
	resourceManagerV3URL    = "https://cloudresourcemanager.googleapis.com/v3"
	accessContextManagerURL = "https://accesscontextmanager.googleapis.com/v1"
)

const maxRetries = 3

// retryBackoff is the wait before the first retry; each further retry waits twice as long.
var retryBackoff = time.Second

// Client performs authenticated Google Cloud REST requests.
type Client struct {
	HTTP *http.Client
	Auth Authorizer

	bindingsMu sync.Mutex
	bindings   map[bindingsKey]cachedBindings
}

// RequestError reports a failed request, carrying the status and message Google Cloud answered
// with.
type RequestError struct {
	URL        string
	StatusCode int
	Status     string
	Message    string
}

func (e *RequestError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("request to %s failed: %s", e.URL, e.Status)
	}
	return fmt.Sprintf("request to %s failed: %s: %s", e.URL, e.Status, e.Message)
}

// validateName fails when a resource name argument does not match the pattern its API method
// declares.
func validateName(argument, value string, pattern *regexp.Regexp) error {
	if !pattern.MatchString(value) {
		return fmt.Errorf("parameter %q value %q does not match the pattern %q", argument, value, pattern.String())
	}
	return nil
}

// escapeName returns a resource name with each of its slash-separated segments escaped for use
// in a URL path.
func escapeName(name string) string {
	segments := strings.Split(name, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// retryable reports whether a response status is worth repeating the request for.
func retryable(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

// do performs an authenticated request with body encoded as JSON when it is not nil, retrying a
// connection failure, 429 or 5xx answer up to maxRetries times with exponential backoff, and
// decodes the JSON response into out.
func (c *Client) do(ctx context.Context, method, requestURL string, body, out any) error {
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = encoded
	}

	var responseBody []byte
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryBackoff << (attempt - 1)):
			}
		}
		request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if authorization := RequestAuthorization(ctx); authorization != "" {
			request.Header.Set("Authorization", authorization)
		} else if err := c.Auth.Authorize(ctx, request); err != nil {
			return err
		}

		response, err := c.HTTP.Do(request)
		if err != nil {
			if attempt < maxRetries && ctx.Err() == nil {
				continue
			}
			return fmt.Errorf("request to %s failed: %w", requestURL, err)
		}
		responseBody, err = io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return fmt.Errorf("request to %s failed: %w", requestURL, err)
		}
		if response.StatusCode < 300 {
			break
		}
		if retryable(response.StatusCode) && attempt < maxRetries {
			continue
		}
		var failure struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		message := failure.Error.Message
		if failure.Error.Status != "" && message != "" {
			message = failure.Error.Status + ": " + message
		}
		return &RequestError{URL: requestURL, StatusCode: response.StatusCode, Status: response.Status, Message: message}
	}

	if len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return fmt.Errorf("response from %s is not the expected JSON: %w", requestURL, err)
	}
	return nil
}
