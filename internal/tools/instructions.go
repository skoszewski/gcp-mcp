package tools

const instructionsOverview = `Read-only access to the GCP side of an investigation: Cloud Audit Logs, VPC Service Controls
perimeters and access levels, project IAM policies and project identifiers.

When a log shows a GCP-side denial or misconfiguration -- a VPC Service Controls violation, a
permission-denied error, or any other GCP API error -- follow it up with gcp_query_cloud_logging
for the audit entries, gcp_get_service_perimeter_policy for a perimeter named in a violation,
gcp_get_access_level for an access level named in a violation or in a perimeter's ingress/egress
policy (its allowed IP ranges, members and device policy are not derivable from its name),
gcp_get_iam_roles_for_member or gcp_get_iam_policy to check what an identity actually holds
before concluding a role is missing, and gcp_resolve_project_identifiers whenever a bare project
number turns up. Scope a log search to the window of the event being investigated: pass its
start and end times, such as a pipeline run's start_time and finish_time.`

const instructionsAccess = `Google Cloud decides what this server can reach: every call runs as one identity, and a
request for something that identity cannot see fails. When a result says permission was denied,
or that something does not exist although its name is right, tell the user this server cannot
reach it rather than looking for a way around it or answering from guesswork.`

// Instructions are the server instructions sent to the client at initialize.
const Instructions = instructionsOverview + "\n\n" + instructionsAccess
