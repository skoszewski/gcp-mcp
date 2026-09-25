package tools

const queryCloudLoggingDescription = `Search Cloud Audit Logs for any GCP-side issue behind the event being investigated.

Use this for VPC Service Controls denials, IAM permission errors, policy changes, or any
other GCP API activity worth investigating -- not just one specific kind of entry.`

const getServicePerimeterPolicyDescription = `Fetch a VPC Service Controls perimeter's policy from the Access Context Manager API.`

const getAccessLevelDescription = `Fetch a VPC Service Controls access level's definition from the Access Context Manager API.

Use this once a VPC SC denial's metadata.accessLevels, or a perimeter's ingress/egress policy
source, names an access level and you need to see what it actually requires -- allowed IP
ranges, member identities, device policy -- rather than guessing from the name.`

const getIAMPolicyDescription = `Fetch the full current IAM policy bindings on a GCP project via Cloud Resource Manager.

Use this when you don't yet know which identity or role is relevant and need to see
everything at once. To check one specific identity's roles directly, use
gcp_get_iam_roles_for_member instead.

A binding's condition, when present, restricts it to a subset of resources or requests (e.g.
by resource name, or a time window) -- a member listed under a role is not actually granted
it for every request unless its condition (if any) is also satisfied.`

const getIAMRolesForMemberDescription = `Fetch the IAM roles a specific member currently holds on a GCP project.

Use this once you've identified the identity that hit a permission-denied error (e.g. a
service account named in the error text, or authenticationInfo.principalEmail from a
gcp_query_cloud_logging result) to confirm exactly what it currently has, before recommending a
role to grant -- don't guess whether a role is missing from the error text alone.

A role's condition, when present, restricts it to a subset of resources or requests (e.g. by
resource name, or a time window) -- holding a role does not mean it applies to every request
unless its condition (if any) is also satisfied, which can explain a permission-denied error
even though the role is listed here.`

const resolveProjectIdentifiersDescription = `Resolve GCP projects' IDs, numbers and display names from any of the three.

Use this whenever the logs or another tool's result mention a bare project number (a plain
digit string, e.g. in a resource path like
"//cloudresourcemanager.googleapis.com/projects/123456789012" or a service account's project)
and you need the human-readable project ID/display name, or vice versa.

Several projects can be resolved in one call, comma-separated, so a result listing many of
them costs one call rather than one per project. A project that cannot be resolved comes back
carrying an error instead of failing the call, so one bad entry does not cost you the rest.`

const noScopeMessage = `scope is empty; pass a Cloud Logging resource name such as 'projects/<project-id>'`

const noFilterMessage = `filter_expression must not be empty`

const noProjectMessage = `project must not be empty; pass a project ID or number seen in the logs`
