package clioutput

import (
	"bytes"
	"log/slog"
	"testing"
)

func capture(color bool, write func()) string {
	var buffer bytes.Buffer
	originalOut, originalColored := out, colored
	defer func() { out, colored = originalOut, originalColored }()
	out, colored = &buffer, color
	write()
	return buffer.String()
}

func TestPlainOutput(t *testing.T) {
	got := capture(false, func() {
		Info("created %d", 2)
		Error("no %s", "organization")
		Table([][]string{{"Scope:", "vso.build"}, {"Authorization ID:", "a1"}})
	})
	want := "created 2\nError: no organization\n  Scope:             vso.build\n  Authorization ID:  a1\n"
	if got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestHandler(t *testing.T) {
	got := capture(false, func() {
		logger := slog.New(NewHandler(slog.LevelDebug))
		logger.Debug("tool call", "tool", "gcp_get_iam_policy", "arguments", `{"resource":"x"}`)
		logger.Info("stopping server")
		logger.Error("server failed", "error", "unknown --transport")
	})
	want := "  [TOOL CALL] gcp_get_iam_policy {\"resource\":\"x\"}\n" +
		"  Stopping server\n" +
		"Error: server failed: unknown --transport\n"
	if got != want {
		t.Errorf("output = %q, want %q", got, want)
	}

	got = capture(true, func() { slog.New(NewHandler(slog.LevelInfo)).Warn("slow request") })
	if got != yellow+"  Slow request"+reset+"\n" {
		t.Errorf("colored output = %q", got)
	}
}

func TestColoredOutput(t *testing.T) {
	got := capture(true, func() { Success("done") })
	if got != green+"done"+reset+"\n" {
		t.Errorf("output = %q", got)
	}
}
