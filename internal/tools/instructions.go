package tools

const instructionsOverview = `Read-only access to the GCP side of an investigation: Cloud Audit Logs, VPC Service Controls
access policies, perimeters and access levels, the organization, folder and project hierarchy,
IAM policies, roles and service accounts, and organization policies.

When a log shows a GCP-side denial or misconfiguration -- a VPC Service Controls violation, a
permission-denied error, or any other GCP API error -- follow it up with gcp_query_cloud_logging
for the audit entries, gcp_get_service_perimeter_policy for a perimeter named in a violation,
gcp_get_access_level for an access level named in a violation or in a perimeter's ingress/egress
policy (its allowed IP ranges, members and device policy are not derivable from its name),
gcp_get_iam_roles_for_member or gcp_get_iam_policy to check what an identity actually holds
before concluding a role is missing, and gcp_resolve_project_identifiers whenever a bare project
number turns up. Scope a log search to the window of the event being investigated: pass its
start and end times, such as a pipeline run's start_time and finish_time.

For a permission-denied error whose audit entry gives the principal, resource and permission,
gcp_troubleshoot_iam_permission gives the verdict across inherited, group and deny policies.
gcp_get_role shows whether a role includes a permission, gcp_get_project_ancestry the folders and
organization whose bindings a project inherits, gcp_get_service_account the email behind a
numeric service account ID, and gcp_search_iam_policies where a member holds roles anywhere.
gcp_get_effective_org_policy explains a denial that names an organization policy constraint.
gcp_list_access_policies and gcp_list_service_perimeters find the perimeters around a project
before any violation has named one; gcp_list_organizations, gcp_list_folders and
gcp_list_projects browse the resource hierarchy.`

const instructionsAccess = `Google Cloud decides what this server can reach: every call runs as one identity, and a
request for something that identity cannot see fails. When a result says permission was denied,
or that something does not exist although its name is right, tell the user this server cannot
reach it rather than looking for a way around it or answering from guesswork.`

// Instructions are the server instructions sent to the client at initialize.
const Instructions = instructionsOverview + "\n\n" + instructionsAccess
