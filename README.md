# gcp-mcp

An MCP server that gives an AI client read-only access to the Google Cloud side of an
investigation: Cloud Audit Logs, VPC Service Controls perimeters and access levels, project IAM
policies and project identifiers. It runs as a binary or as a container, over Streamable HTTP or
stdio.

## Tools

| Tool | Purpose |
| --- | --- |
| `gcp_query_cloud_logging` | Cloud Logging entries matching a filter expression, newest first, in a time window |
| `gcp_get_service_perimeter_policy` | A VPC Service Controls perimeter's enforced and dry-run configuration |
| `gcp_get_access_level` | A VPC Service Controls access level's conditions: IP ranges, members, regions, device policy |
| `gcp_get_iam_policy` | A project's IAM policy bindings |
| `gcp_get_iam_roles_for_member` | The roles one member holds on a project |
| `gcp_resolve_project_identifiers` | Project IDs, numbers and display names from any of them, several per call |

`gcp_query_cloud_logging` searches the project given as `scope`, or the default project described
below when a call names none. A bare project ID is prefixed with `projects/`. A filter that
restricts no `timestamp`, after `start`, `end` or `freshness` are applied, is limited to the last
24 hours. The tool reads every page of matching entries, 50 per request.

`gcp_get_iam_policy` and `gcp_get_iam_roles_for_member` reuse a project's bindings for five
minutes for the same credential.

`gcp_resolve_project_identifiers` reports a project it cannot resolve with an `error` field
instead of failing the call.

## Authentication

With the default `--auth adc`, the server uses the Application Default Credentials, the first
source found:

1. The file named by `GOOGLE_APPLICATION_CREDENTIALS`.
2. The gcloud well-known file written by `gcloud auth application-default login`.
3. The metadata server, when the server runs on Google Cloud.

The server fails at startup when none is found. `--auth none` configures no credential; every
call then needs an `Authorization` header from the MCP client, described below.

The identity needs these permissions on the resources it reads:

- `logging.logEntries.list`, e.g. the Logs Viewer role, and `logging.privateLogEntries.list`,
  e.g. the Private Logs Viewer role, for Data Access audit logs
- `accesscontextmanager.servicePerimeters.get` and `accesscontextmanager.accessLevels.get`,
  e.g. the Access Context Manager Reader role on the organization
- `resourcemanager.projects.getIamPolicy` and `resourcemanager.projects.get`, e.g. the Security
  Reviewer and Browser roles

With user credentials, Google Cloud charges the Resource Manager and Access Context Manager
calls to a quota project. The server sends the credentials file's `quota_project_id`, which
`gcloud auth application-default set-quota-project` sets, or `GOOGLE_CLOUD_QUOTA_PROJECT`
when it is set.

### Default project

`gcp_query_cloud_logging` called without `scope` searches the first of:

1. `GOOGLE_CLOUD_PROJECT`.
2. `GCLOUD_PROJECT`.
3. The project of the credentials: a service account key's `project_id`, or the metadata
   server's project.
4. For user credentials, the project configured in the Google Cloud CLI
   (`gcloud config get-value project`), when the CLI is installed.

The project in use is logged at startup. Without one, every `gcp_query_cloud_logging` call has to
name its `scope`.

### Credentials sent by the MCP client

Over the HTTP transport, an `Authorization` header on the MCP request replaces the configured
credential for that request. The server forwards the value unchanged to Google Cloud, so it takes
the form `Bearer <token>`, where `<token>` is an OAuth access token with the `cloud-platform`
scope, e.g. from `gcloud auth print-access-token`. A request with its own header sends no quota
project.

A client without the header, and every client on stdio, uses the configured credential; with
`--auth none` such a call fails. For example, in a Claude Code configuration:

```json
{
  "mcpServers": {
    "gcp": {
      "type": "http",
      "url": "http://127.0.0.1:8889/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Running

```bash
gcp-mcp
gcp-mcp --transport stdio
```

The first form serves Streamable HTTP at `http://127.0.0.1:8889/mcp`; the second serves stdio for
an MCP client that starts the server itself. The container image runs `gcp-mcp` bound to
`0.0.0.0`. It has no Google Cloud CLI, so the credentials file is mounted into it:

```bash
docker run --rm -p 127.0.0.1:8889:8889 \
  --mount type=bind,source=$HOME/.config/gcloud/application_default_credentials.json,target=/var/run/gcp/credentials.json,readonly \
  -e GOOGLE_APPLICATION_CREDENTIALS=/var/run/gcp/credentials.json \
  -e GOOGLE_CLOUD_PROJECT=my-project \
  gcp-mcp:latest
```

The image runs as the distroless `nonroot` user (UID 65532), which must be able to read the
mounted file.

### Kubernetes

The Helm chart in `charts/gcp-mcp` runs the container image as a Deployment behind a Service.
The Deployment and the Service are named after the Helm release. The endpoint has no
authentication of its own, so anyone who can reach the Service uses the server's credentials.

| Value | Default | Meaning |
| --- | --- | --- |
| `image` | `gcp-mcp:latest` | Container image; it must be pullable by the cluster |
| `serviceAccountName` | | Kubernetes service account the pod runs as, e.g. one bound to a Google service account through Workload Identity Federation for GKE |
| `credentialsSecret` | | Secret holding a credentials file under the key `credentials.json`, mounted as `GOOGLE_APPLICATION_CREDENTIALS`; empty to use the metadata server |
| `project` | | Default project, set as `GOOGLE_CLOUD_PROJECT` |
| `port` | `8889` | Port the server listens on and the Service exposes |
| `serviceType` | `LoadBalancer` | Service type, e.g. `ClusterIP` for access from inside the cluster only |

On GKE with Workload Identity Federation, the pod takes its credentials from the metadata server:

```bash
helm install gcp-mcp charts/gcp-mcp --set image=<registry>/gcp-mcp:latest \
  --set serviceAccountName=gcp-mcp --set project=my-project
```

Elsewhere, create the Secret from a service account key file, then install the chart:

```bash
kubectl create secret generic gcp-mcp --from-file=credentials.json=key.json
helm install gcp-mcp charts/gcp-mcp --set image=<registry>/gcp-mcp:latest \
  --set credentialsSecret=gcp-mcp --set project=my-project
```

## Development scripts

The `scripts` directory of the repository holds helpers for development.

Building the binary requires Go 1.27.

```bash
scripts/build.sh
scripts/run.sh
```

`scripts/build.sh` builds `bin/gcp-mcp` in the repository; `GOOS` and `GOARCH` select another
target platform. `scripts/run.sh` runs `bin/gcp-mcp` over the stdio transport and passes its
arguments to it, so `scripts/run.sh --transport http` serves `http://127.0.0.1:8889/mcp` instead.
It exports the variables in the `.env` file in the repository root to the server when that file
exists. `.env` is a Docker environment file.

The Bash container scripts use Docker when it is installed and Apple `container` otherwise.

```bash
scripts/build_container.sh
scripts/run_container.sh
scripts/run_container.sh --transport stdio
```

`scripts/build_container.sh` builds the `gcp-mcp:latest` image for the host's architecture;
`ARCH` set to `amd64`, `arm64` or `amd64,arm64` selects others. `scripts/run_container.sh`
publishes the server on `127.0.0.1:8889` and passes its arguments to `gcp-mcp`. It mounts the
file named by `GOOGLE_APPLICATION_CREDENTIALS`, or else the gcloud well-known file, read-only into
the container, passes the variables in the `.env` file in the repository root when that file
exists, and passes `GOOGLE_CLOUD_PROJECT`, `GCLOUD_PROJECT` and `GOOGLE_CLOUD_QUOTA_PROJECT` when
they are set in the calling shell. `IMAGE` overrides the image name (`gcp-mcp:latest`) and `PORT`
the host port.

PowerShell 7 scripts do the same on any platform, with Docker as the container runtime:

```powershell
scripts/build.ps1
scripts/run.ps1
scripts/build_container.ps1
scripts/run_container.ps1
```

`scripts/build.ps1` gives a binary built for Windows the `.exe` extension.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--transport` | `http` | `http` (Streamable HTTP) or `stdio` |
| `--auth` | `adc` | `adc` or `none`; see Authentication |
| `--host` | `127.0.0.1` | Address the HTTP server binds to; the container image sets `0.0.0.0` |
| `--port` | `8889` | HTTP port |
| `--path` | `/mcp` | HTTP path of the MCP endpoint |
| `--debug[=N]` | `0` | `1` logs tool calls, `2` adds incoming HTTP requests, `3` adds the MCP library's own logging |
| `--log-style` | `auto` | `human`, `daemon`, or `auto` for `human` when stdout is a terminal; see Logging |

## Logging

`gcp-mcp` logs to stderr in one of two styles. `human` starts with a banner listing the version,
authentication method, default project, tools and endpoint, and writes one readable line per
event, colored when stderr is a terminal. `daemon` writes timestamped `key=value` records for a
container runtime, service manager or MCP client to collect. `--log-style auto`, the default,
uses `human` when stdout is a terminal and `daemon` otherwise.

## Client configuration

Streamable HTTP, for a client that supports it:

```json
{
  "mcpServers": {
    "gcp": {
      "type": "http",
      "url": "http://127.0.0.1:8889/mcp"
    }
  }
}
```

stdio, with the binary:

```json
{
  "mcpServers": {
    "gcp": {
      "command": "/usr/local/bin/gcp-mcp",
      "args": ["--transport", "stdio"],
      "env": { "GOOGLE_CLOUD_PROJECT": "my-project" }
    }
  }
}
```

## Development

```bash
go vet ./...
go test ./...
```
