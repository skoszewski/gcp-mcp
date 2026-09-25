// Package clioutput writes command-line output to stderr, leaving stdout for the data a command
// produces. Output is colored when stderr is a terminal.
package clioutput

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

const (
	red    = "\033[0;31m"
	green  = "\033[0;32m"
	yellow = "\033[0;33m"
	blue   = "\033[0;34m"
	cyan   = "\033[0;36m"
	reset  = "\033[0m"
)

const rule = "=========================================="

var (
	out     io.Writer = os.Stderr
	colored           = IsTerminal(os.Stderr)
)

// IsTerminal reports whether file is a terminal.
func IsTerminal(file *os.File) bool {
	return term.IsTerminal(int(file.Fd()))
}

func colorize(color, text string) string {
	if !colored || color == "" {
		return text
	}
	return color + text + reset
}

func line(color, format string, args []any) {
	fmt.Fprintln(out, colorize(color, fmt.Sprintf(format, args...)))
}

// Banner writes title between two cyan rules.
func Banner(title string) {
	fmt.Fprintln(out, colorize(cyan, rule))
	fmt.Fprintln(out, colorize(cyan, title))
	fmt.Fprintln(out, colorize(cyan, rule))
}

// Emphasize returns text in cyan, for embedding in a line.
func Emphasize(text string) string {
	return colorize(cyan, text)
}

// Info writes a plain line formatted as by fmt.Sprintf.
func Info(format string, args ...any) {
	line("", format, args)
}

// Success writes a green line formatted as by fmt.Sprintf.
func Success(format string, args ...any) {
	line(green, format, args)
}

// Warning writes a yellow line formatted as by fmt.Sprintf.
func Warning(format string, args ...any) {
	line(yellow, format, args)
}

// Error writes a red line prefixed with "Error: " and formatted as by fmt.Sprintf.
func Error(format string, args ...any) {
	line(red, "Error: "+format, args)
}

// Fail writes err as an Error line and exits with status 1.
func Fail(err error) {
	Error("%v", err)
	os.Exit(1)
}

// Table writes rows as columns aligned with two spaces between them, each row indented by two
// spaces.
func Table(rows [][]string) {
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintln(writer, "  "+strings.Join(row, "\t"))
	}
	writer.Flush()
}
