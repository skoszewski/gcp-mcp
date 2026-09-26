// Command gcp-mcp serves Google Cloud audit logs, VPC Service Controls policies, the resource
// hierarchy, IAM policies, roles and service accounts, and organization policies as MCP tools,
// over Streamable HTTP or stdio.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/skoszewski/gcp-mcp/internal/clioutput"
	"github.com/skoszewski/gcp-mcp/internal/gcp"
	"github.com/skoszewski/gcp-mcp/internal/tools"
)

// version is set at build time with -ldflags "-X main.version=<version>".
var version = "dev"

const (
	serverName      = "gcp-mcp"
	shutdownTimeout = 15 * time.Second
	httpTimeout     = 2 * time.Minute
	debugToolCalls  = 1
	debugRequests   = 2
	debugSDK        = 3
)

const usageText = `Usage: gcp-mcp [flags]

Run an MCP server exposing read-only Google Cloud investigation tools -- Cloud Audit Logs, VPC
Service Controls access policies, perimeters and access levels, the organization, folder and
project hierarchy, IAM policies, roles and service accounts, and organization policies.

Every tool call reaches whatever the authenticated identity is authorized for in Google Cloud.

Authentication with --auth auto uses an access token as the Google Cloud CLI does, first match
wins, and otherwise the Application Default Credentials:
  CLOUDSDK_AUTH_ACCESS_TOKEN        access token
  CLOUDSDK_AUTH_ACCESS_TOKEN_FILE   file holding an access token, read for every request

The Application Default Credentials, used by --auth adc, are the first source found:
  GOOGLE_APPLICATION_CREDENTIALS    credentials file
  gcloud well-known file            application_default_credentials.json in CLOUDSDK_CONFIG, or
                                    in the gcloud default configuration directory when it is
                                    unset, written by gcloud auth application-default login
  metadata server                   the attached service account on Google Cloud

The project gcp_query_cloud_logging searches when a call names none is GOOGLE_CLOUD_PROJECT,
then GCLOUD_PROJECT, then the credentials' project, then the Google Cloud CLI's configured
project. GOOGLE_CLOUD_QUOTA_PROJECT overrides the credentials' quota project.

Flags:
      --transport <name>     MCP transport: http (Streamable HTTP) or stdio (default: http)
      --auth <method>        authentication: auto (access token when set, otherwise Application
                             Default Credentials), access-token, adc, or none (no credential
                             of the server's own; the MCP client sends an Authorization
                             header) (default: auto)
      --host <address>       address the HTTP server binds to (default: 127.0.0.1)
      --port <port>          port the HTTP server listens on (default: 8889)
      --path <path>          URL path of the MCP endpoint (default: /mcp)
      --debug[=<level>]      debug output: 1 (a bare --debug) logs tool calls, 2 adds HTTP
                             requests, 3 adds the MCP library's own logging
      --log-style <style>    human (colored, readable lines), daemon (timestamped key=value
                             records) or auto: human when stdout is a terminal (default: auto)
  -h, --help                 show this help

Examples:
  gcp-mcp
  gcp-mcp --port 9000 --path /gcp
  gcp-mcp --transport stdio
`

var debugDescriptions = map[int]string{
	debugToolCalls: "logging every tool call with its arguments",
	debugRequests:  "logging every tool call with its arguments, and each HTTP request",
	debugSDK:       "logging every tool call, each HTTP request, and the MCP library's own output",
}

// debugLevel is the --debug flag: a bare --debug sets level 1, --debug=N sets level N.
type debugLevel int

func (d *debugLevel) String() string {
	return strconv.Itoa(int(*d))
}

func (d *debugLevel) Set(value string) error {
	if value == "true" {
		*d = debugToolCalls
		return nil
	}
	level, err := strconv.Atoi(value)
	if err != nil || level < 0 || level > debugSDK {
		return errors.New("must be 0, 1, 2 or 3")
	}
	*d = debugLevel(level)
	return nil
}

func (d *debugLevel) IsBoolFlag() bool {
	return true
}

type options struct {
	transport   string
	auth        string
	host        string
	port        int
	path        string
	debug       debugLevel
	logStyle    string
	interactive bool
}

func parseFlags() options {
	var opts options
	flags := flag.CommandLine
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), usageText)
	}

	flags.StringVar(&opts.transport, "transport", "http", "")
	flags.StringVar(&opts.auth, "auth", gcp.AuthAuto, "")
	flags.StringVar(&opts.host, "host", "127.0.0.1", "")
	flags.IntVar(&opts.port, "port", 8889, "")
	flags.StringVar(&opts.path, "path", "/mcp", "")
	flags.Var(&opts.debug, "debug", "")
	flags.StringVar(&opts.logStyle, "log-style", "auto", "")

	flag.Parse()
	return opts
}

func main() {
	opts := parseFlags()
	level := slog.LevelInfo
	if opts.debug > 0 {
		level = slog.LevelDebug
	}
	switch opts.logStyle {
	case "auto":
		opts.interactive = clioutput.IsTerminal(os.Stdout)
	case "human":
		opts.interactive = true
	case "daemon":
		opts.interactive = false
	default:
		clioutput.Fail(fmt.Errorf("unknown --log-style %q; use auto, human or daemon", opts.logStyle))
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	if opts.interactive {
		handler = clioutput.NewHandler(level)
	}
	slog.SetDefault(slog.New(handler))

	if err := run(opts); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if opts.transport != "http" && opts.transport != "stdio" {
		return fmt.Errorf("unknown --transport %q; use http or stdio", opts.transport)
	}
	if !strings.HasPrefix(opts.path, "/") {
		return fmt.Errorf("--path %q must start with /", opts.path)
	}

	var sdkLogger *slog.Logger
	if opts.debug >= debugSDK {
		sdkLogger = slog.Default()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authorizer, err := gcp.NewAuthorizer(ctx, opts.auth, os.Getenv)
	if err != nil {
		return err
	}
	client := &gcp.Client{HTTP: &http.Client{Timeout: httpTimeout}, Auth: authorizer}

	server := mcp.NewServer(
		&mcp.Implementation{Name: serverName, Version: version},
		&mcp.ServerOptions{Instructions: tools.Instructions, Logger: sdkLogger},
	)
	toolNames := tools.Register(server, client)
	if opts.interactive {
		printBanner(opts, authorizer, toolNames)
	} else {
		slog.Info("starting server", "version", version, "transport", opts.transport,
			"authentication", authorizer.Method(), "project", authorizer.Project(),
			"debug", int(opts.debug), "tools", strings.Join(toolNames, ","))
	}

	if opts.transport == "stdio" {
		return server.Run(ctx, &mcp.StdioTransport{})
	}
	return serveHTTP(ctx, server, opts, sdkLogger)
}

// serveHTTP serves server as a stateless Streamable HTTP endpoint until ctx is cancelled.
func serveHTTP(ctx context.Context, server *mcp.Server, opts options, sdkLogger *slog.Logger) error {
	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, Logger: sdkLogger},
	)
	if opts.debug >= debugRequests {
		next := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("http request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			next.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	mux.Handle(opts.path, handler)

	httpServer := &http.Server{Addr: net.JoinHostPort(opts.host, strconv.Itoa(opts.port)), Handler: mux}
	if !opts.interactive {
		slog.Info("listening", "endpoint", "http://"+httpServer.Addr+opts.path)
	}
	failed := make(chan error, 1)
	go func() {
		failed <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	slog.Info("stopping server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// printBanner writes the settings, the tools and the endpoint for a person reading the terminal.
func printBanner(opts options, authorizer gcp.Authorizer, toolNames []string) {
	clioutput.Banner("Serving Google Cloud investigation tools over MCP")
	clioutput.Info("  Version: %s", version)
	clioutput.Info("  Authentication: %s", authorizer.Method())
	if project := authorizer.Project(); project != "" {
		clioutput.Info("  Default project: %s", project)
	} else {
		clioutput.Warning("  Default project: none; gcp_query_cloud_logging calls must name a scope")
	}
	if opts.debug > 0 {
		clioutput.Warning("  Debug: %s", debugDescriptions[int(opts.debug)])
	}
	clioutput.Info("  Tools (%d):", len(toolNames))
	for _, name := range toolNames {
		clioutput.Info("    - %s", name)
	}
	if opts.transport == "stdio" {
		clioutput.Info("  Transport: stdio")
	} else {
		endpoint := fmt.Sprintf("http://%s%s", net.JoinHostPort(opts.host, strconv.Itoa(opts.port)), opts.path)
		clioutput.Info("  Endpoint: %s", clioutput.Emphasize(endpoint))
	}
	clioutput.Info("")
}
