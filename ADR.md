# Architecture Decision Records

## ADR-001: Port of the ado-pipeline-logs-analyzer GCP investigation tools

**Decision:** The server implements the `gcp_` tools of the Python `ado-pipeline-logs-analyzer`
MCP server with the same names, arguments, result fields, descriptions and argument error
messages. The
Azure DevOps tools, AI analysis and CLI subcommands are not part of it; `ado-mcp` serves the
Azure DevOps tools.

**Reason:** Clients and prompts written against the Python server keep working, and the
model-facing text that was tuned there is reused unchanged.

**Consequence:** `gcp_query_cloud_logging` returns its entries under an `entries` key, because
an MCP structured result is an object, where the Python function returns a bare list.

## ADR-002: Google Cloud REST APIs over net/http

**Decision:** The server calls the Cloud Logging v2, Access Context Manager v1, Cloud Resource
Manager v1 and v3, IAM v1, Policy Troubleshooter v3, Organization Policy v2 and Cloud Asset v1
REST APIs with `net/http`. Access tokens come from `golang.org/x/oauth2/google`, which resolves
the Application Default Credentials.

**Reason:** Each tool makes one or two plain GET or POST requests, and the generated clients in
`google.golang.org/api` or `cloud.google.com/go/logging` would add a large dependency tree for
them. Resolving the Application Default Credentials and refreshing their tokens is not something
to reimplement.

**Consequence:** Behavior the Python client libraries supply is implemented here: resource name
validation against the pattern each API method declares, three retries of a connection failure,
429 or 5xx answer with exponential backoff, and the `X-Goog-User-Project` header carrying the
credentials' quota project.

## ADR-003: Behavior of the Python Cloud Logging client reproduced

**Decision:** `gcp_query_cloud_logging` restricts a filter that does not mention `timestamp` to
the last 24 hours, and reads every page of matching entries, 50 per request.

**Reason:** `google-cloud-logging`'s `Client.list_entries`, which the Python tool calls, adds
that default time restriction, and iterating its result follows every page. The tool behaves the
same way against the REST API.

**Consequence:** The `start` argument description states the 24-hour default. The Python
description, which says an omitted time window applies no restriction at all, is not reused.

## ADR-004: Default project resolved as google-auth does

**Decision:** The default project is `GOOGLE_CLOUD_PROJECT`, then `GCLOUD_PROJECT`, then the
credentials' project, then for user credentials the Google Cloud CLI's configured project. It is
resolved once at startup.

**Reason:** The Python tool uses the project `google.auth.default()` returns, which follows that
order, and caches it for the life of the process. `golang.org/x/oauth2/google` reports only the
credentials' own project.

## ADR-005: IAM bindings cached for five minutes per credential

**Decision:** `gcp_get_iam_policy` and `gcp_get_iam_roles_for_member` share a resource's bindings
for five minutes, keyed by resource and by the `Authorization` header of the MCP request.

**Reason:** An investigation typically calls both for the same project, and Cloud Resource
Manager has a shared read quota. The Python server caches the bindings for the life of the
process, which in a long-running server reports a policy that has since changed. Keying by the
header keeps one client's credential from reading bindings fetched with another's.

## ADR-006: Authorization header of the MCP request overrides the configured credential

**Decision:** When the HTTP request carrying a tool call has an `Authorization` header, the
server sends its value unchanged as the `Authorization` header of that call's Google Cloud
requests, without a quota project header, in place of the Application Default Credentials.
`--auth none` holds no credential and relies on the header. The header is not logged.

**Reason:** Different users need different identities, while the configured credential gives
every client the server's single identity. The quota project belongs to the server's
credentials, and the client's identity may not be allowed to use it.

## ADR-007: No Google Cloud CLI in the container image

**Decision:** The image is a static Go binary on `distroless/static`. Inside the container the
credentials come from a mounted credentials file or from the metadata server.

**Reason:** The Google Cloud CLI would add a Python runtime and several hundred megabytes to an
otherwise minimal image. Only the default project lookup uses it, and `GOOGLE_CLOUD_PROJECT`
replaces that.

## ADR-008: Stateless Streamable HTTP and stdio transports, human and daemon log styles

**Decision:** The server follows `ado-mcp`: stateless Streamable HTTP by default and stdio for
clients that start the server themselves, human or daemon log style chosen by `--log-style`,
container scripts that prefer Docker and fall back to Apple `container`, and a Helm chart. Its
default port is 8889.

**Reason:** The two servers are used side by side, so they run, log and deploy the same way, and
their default ports differ so both can run on one host.

**Consequence:** The container scripts mount the credentials file with
`--mount type=bind,source=...,target=...,readonly`, a form both Docker and Apple `container`
accept.

## ADR-009: CLOUDSDK_CONFIG locates the gcloud well-known file

**Decision:** When `GOOGLE_APPLICATION_CREDENTIALS` is unset and `CLOUDSDK_CONFIG` is set, the
server reads `application_default_credentials.json` from the `CLOUDSDK_CONFIG` directory, and
without that file falls back to the metadata server only. Otherwise it uses
`google.FindDefaultCredentials`.

**Reason:** `golang.org/x/oauth2/google` looks for the well-known file only in `~/.config/gcloud`
or `%APPDATA%\gcloud`, while google-auth and the Google Cloud CLI take the configuration
directory from `CLOUDSDK_CONFIG`. Tools such as cloud-select switch gcloud profiles by setting
it, so ignoring it would authenticate as another profile's identity, and take the default
project from the selected profile but the credentials from another.

## ADR-010: Access token from the Google Cloud CLI variables

**Decision:** `--auth auto`, the default, uses `CLOUDSDK_AUTH_ACCESS_TOKEN`, then the file named
by `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`, and the Application Default Credentials only when neither
is set. `--auth access-token` and `--auth adc` force one method. The token is not refreshed; the
file is read for every request. The `auth/access_token_file` property in a gcloud configuration
file is not read.

**Reason:** The Google Cloud CLI gives these two variables precedence over every other credential
(`googlecloudsdk/core/credentials/store.py`), so an environment prepared for `gcloud` with a
token authenticates the server as the same identity. A token has no refresh credential, so a
long-running server can only pick up a new one by rereading its file. Reading gcloud
configuration files would mean reimplementing gcloud's property resolution for one property,
whose environment variable form is already supported.

## ADR-011: Lookup tools beyond the Python port

**Decision:** The server adds tools that the Python server does not have. They cover roles,
project ancestry, Policy Troubleshooter, service accounts, access policies and perimeter
listings, effective organization policies, Cloud Asset IAM policy search, and organization,
folder and project listings. `gcp_get_iam_policy` and `gcp_get_iam_roles_for_member` also accept
`folders/<id>` and `organizations/<id>`, and a bare value is still a project ID. Project policies
are read with Resource Manager v1, as before, and folder and organization policies with v3,
because v1 has no folder method.

**Reason:** The ported tools cannot explain inherited bindings, group membership, deny
policies, custom role contents, organization policy constraints, or which perimeter protects a
project before a violation names one, and investigations stalled at those points. Existing
arguments keep their meaning, so clients written against the Python server still work.

**Consequence:** ADR-001 holds for the ported tools only. `gcp_troubleshoot_iam_permission` drops
the raw policy of each explained allow policy and the bindings whose role does not include the
permission, because those cannot grant it and account for most of the response.
`gcp_get_service_account` looks the account up with the `projects/-` wildcard, for which the IAM
API documents that a missing account can answer 403 instead of 404. It then reads the account's
own policy under the name returned. The list and search tools read every page, as
`gcp_query_cloud_logging` does.
