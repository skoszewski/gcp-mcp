package gcp

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEntriesPageSize is the number of entries each entries:list request asks for.
const LogEntriesPageSize = 50

// defaultWindow is the lookback added to a filter that restricts no timestamp.
const defaultWindow = 24 * time.Hour

var freshnessRE = regexp.MustCompile(`^(\d+)([smhd])$`)

var freshnessUnits = map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}

// LogEntry is one Cloud Logging entry, with whichever payload it carries.
type LogEntry struct {
	Timestamp    *string `json:"timestamp"`
	InsertID     *string `json:"insertId"`
	Severity     *string `json:"severity"`
	LogName      *string `json:"logName"`
	ProtoPayload any     `json:"protoPayload"`
	JSONPayload  any     `json:"jsonPayload"`
	TextPayload  *string `json:"textPayload"`
}

// Payload returns the entry's protoPayload, jsonPayload or textPayload, or nil when it has none.
func (e LogEntry) Payload() any {
	switch {
	case e.ProtoPayload != nil:
		return e.ProtoPayload
	case e.JSONPayload != nil:
		return e.JSONPayload
	case e.TextPayload != nil:
		return *e.TextPayload
	}
	return nil
}

// ParseFreshness parses a duration such as "30m", "24h" or "7d".
func ParseFreshness(freshness string) (time.Duration, error) {
	match := freshnessRE.FindStringSubmatch(freshness)
	if match == nil {
		return 0, fmt.Errorf("invalid freshness '%s'; expected e.g. '30m', '24h', '7d'", freshness)
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("invalid freshness '%s'; expected e.g. '30m', '24h', '7d'", freshness)
	}
	return time.Duration(value) * freshnessUnits[match[2]], nil
}

// TimeFilter returns the Cloud Logging timestamp clause for an explicit start and end, or when
// both are empty for the freshness lookback from now, or "" when all three are empty.
func TimeFilter(freshness, start, end string, now time.Time) (string, error) {
	if start != "" || end != "" {
		var clauses []string
		if start != "" {
			clauses = append(clauses, fmt.Sprintf(`timestamp>="%s"`, start))
		}
		if end != "" {
			clauses = append(clauses, fmt.Sprintf(`timestamp<="%s"`, end))
		}
		return strings.Join(clauses, " AND "), nil
	}
	if freshness == "" {
		return "", nil
	}
	lookback, err := ParseFreshness(freshness)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`timestamp>="%s"`, now.UTC().Add(-lookback).Format(time.RFC3339Nano)), nil
}

// WithDefaultWindow returns filter restricted to the last 24 hours before now when it does not
// mention a timestamp.
func WithDefaultWindow(filter string, now time.Time) string {
	if strings.Contains(strings.ToLower(filter), "timestamp") {
		return filter
	}
	return fmt.Sprintf(`%s AND timestamp>="%s"`, filter, now.UTC().Add(-defaultWindow).Format(time.RFC3339Nano))
}

// LogEntries returns every entry of scope matching filter, newest first, following the page
// token to the last page.
func (c *Client) LogEntries(ctx context.Context, scope, filter string) ([]LogEntry, error) {
	request := struct {
		ResourceNames []string `json:"resourceNames"`
		Filter        string   `json:"filter"`
		OrderBy       string   `json:"orderBy"`
		PageSize      int      `json:"pageSize"`
		PageToken     string   `json:"pageToken,omitempty"`
	}{ResourceNames: []string{scope}, Filter: filter, OrderBy: "timestamp desc", PageSize: LogEntriesPageSize}

	entries := []LogEntry{}
	for {
		var page struct {
			Entries       []LogEntry `json:"entries"`
			NextPageToken string     `json:"nextPageToken"`
		}
		if err := c.do(ctx, http.MethodPost, loggingURL+"/entries:list", request, &page); err != nil {
			return nil, err
		}
		entries = append(entries, page.Entries...)
		if page.NextPageToken == "" {
			return entries, nil
		}
		request.PageToken = page.NextPageToken
	}
}
