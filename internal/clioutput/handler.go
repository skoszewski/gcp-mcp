package clioutput

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Handler is a slog.Handler writing each record as one human-readable line. A record with
// attributes is written as "  [MESSAGE] value value ..." and one without as "  Message"; an
// error is written as "Error: message: value ...". Debug lines are blue, warnings yellow and
// errors red.
type Handler struct {
	mu     *sync.Mutex
	level  slog.Leveler
	values []string
}

// NewHandler returns a Handler writing records at level and above.
func NewHandler(level slog.Leveler) *Handler {
	return &Handler{mu: &sync.Mutex{}, level: level}
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *Handler) Handle(_ context.Context, record slog.Record) error {
	values := append([]string{}, h.values...)
	record.Attrs(func(attr slog.Attr) bool {
		values = appendValues(values, attr)
		return true
	})

	var text string
	switch {
	case record.Level >= slog.LevelError:
		text = "Error: " + record.Message
		if len(values) > 0 {
			text += ": " + strings.Join(values, " ")
		}
	case len(values) == 0:
		text = "  " + capitalize(record.Message)
	default:
		text = "  [" + strings.ToUpper(record.Message) + "] " + strings.Join(values, " ")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintln(out, colorize(levelColor(record.Level), text))
	return err
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.values = append([]string{}, h.values...)
	for _, attr := range attrs {
		clone.values = appendValues(clone.values, attr)
	}
	return &clone
}

func (h *Handler) WithGroup(string) slog.Handler {
	return h
}

func levelColor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return red
	case level >= slog.LevelWarn:
		return yellow
	case level >= slog.LevelInfo:
		return ""
	default:
		return blue
	}
}

// appendValues appends the non-empty values of attr, and of its members when it is a group, with
// runs of whitespace collapsed to one space.
func appendValues(values []string, attr slog.Attr) []string {
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() == slog.KindGroup {
		for _, member := range attr.Value.Group() {
			values = appendValues(values, member)
		}
		return values
	}
	if value := strings.Join(strings.Fields(attr.Value.String()), " "); value != "" {
		values = append(values, value)
	}
	return values
}

func capitalize(text string) string {
	first, size := utf8.DecodeRuneInString(text)
	return string(unicode.ToUpper(first)) + text[size:]
}
