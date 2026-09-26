package tools

const queryCloudLoggingDescription = `Search Cloud Audit Logs for any GCP-side issue behind the event being investigated.

Use this for VPC Service Controls denials, IAM permission errors, policy changes, or any
other GCP API activity worth investigating -- not just one specific kind of entry.`

const getServicePerimeterPolicyDescription = `Fetch a VPC Service Controls perimeter's policy from the Access Context Manager API.`

const getAccessLevelDescription = `Fetch a VPC Service Controls access level's definition from the Access Context Manager API.

Use this once a VPC SC denial's metadata.accessLevels, or a perimeter's ingress/egress policy
source, names an access level and you need to see what it actually requires -- allowed IP
ranges, member identities, device policy -- rather than guessing from the name.`

const getIAMPolicyDescription = `Fetch the full current IAM policy bindings on a GCP project, folder or organization via Cloud Resource Manager.

Use this when you don't yet know which identity or role is relevant and need to see
everything at once. To check one specific identity's roles directly, use
gcp_get_iam_roles_for_member instead.

A binding's condition, when present, restricts it to a subset of resources or requests (e.g.
by resource name, or a time window) -- a member listed under a role is not actually granted
it for every request unless its condition (if any) is also satisfied.`

const getIAMRolesForMemberDescription = `Fetch the IAM roles a specific member currently holds on a GCP project, folder or organization.

Use this once you've identified the identity that hit a permission-denied error (e.g. a
service account named in the error text, or authenticationInfo.principalEmail from a
gcp_query_cloud_logging result) to confirm exactly what it currently has, before recommending a
role to grant -- don't guess whether a role is missing from the error text alone.

A role's condition, when present, restricts it to a subset of resources or requests (e.g. by
resource name, or a time window) -- holding a role does not mean it applies to every request
unless its condition (if any) is also satisfied, which can explain a permission-denied error
even though the role is listed here.

Only direct bindings on the given resource are listed. A member can also hold roles inherited
from the folders and organization above a project, through a group it belongs to, or on the
individual resource it accessed.`

const getRoleDescription = `Fetch an IAM role's definition: its title, launch stage and the permissions it includes.

Use this to confirm whether a role held by an identity actually includes the permission a
denial names, or to choose the narrowest role to recommend -- don't infer a role's
permissions from its name. Works for predefined roles and for project or organization custom
roles.`

const getProjectAncestryDescription = `List the folders and organization above a GCP project, nearest first.

Use this when a project's own IAM policy does not explain an identity's access: roles granted
on an ancestor folder or the organization are inherited by every project below it. Pass each
ancestor to gcp_get_iam_policy or gcp_get_iam_roles_for_member as "folders/<id>" or
"organizations/<id>".`

const troubleshootIAMPermissionDescription = `Ask Policy Troubleshooter whether a principal has a permission on a resource, and why.

This evaluates every IAM allow policy on the resource and its ancestors, group memberships,
binding conditions and IAM deny policies, which the other IAM tools cannot. Use it once an
audit log entry has given the principal, resource and permission of a denial, to get a verdict
rather than reasoning it out from bindings.

overall_access_state is the answer. allow_policies lists each evaluated allow policy with
only the bindings whose role includes the permission; deny_policy_explanation shows whether a
deny policy blocks it. A state of UNKNOWN_INFO means the server's identity could not read some
policy involved, not that access is denied; UNKNOWN_CONDITIONAL means a condition depends on
request attributes, such as the request time or IP address, that this tool does not supply.`

const getServiceAccountDescription = `Fetch a service account's details and the IAM policy attached to the account itself.

Use this when a log names a service account by its numeric unique ID, to find its email and
project, or to check whether it is disabled. The account's own IAM policy shows who may act as
it -- e.g. holders of roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountUser --
not the roles the account holds elsewhere; use gcp_get_iam_roles_for_member or
gcp_search_iam_policies for those. When that policy cannot be read, the account's details are
still returned, with the reason in iam_policy_error.`

const listAccessPoliciesDescription = `List the VPC Service Controls access policies of an organization.

Use this to find the access policy ID gcp_list_service_perimeters needs when no VPC SC audit
log entry has named a perimeter.`

const listServicePerimetersDescription = `List the VPC Service Controls perimeters of an access policy, with the resources each one protects.

Use this to find which perimeters a project belongs to -- pass it as project -- before any
violation has named one, or to see a perimeter's neighbors. resources are enforced;
dry_run_resources are only in the dry-run configuration. Fetch a perimeter's services and
ingress/egress rules with gcp_get_service_perimeter_policy.`

const getEffectiveOrgPolicyDescription = `Fetch the organization policy in effect for one constraint on a project, folder or organization.

Use this when an error names an organization policy constraint (e.g.
"constraints/iam.allowedPolicyMemberDomains", "constraints/gcp.resourceLocations") or
otherwise looks like a permission problem while the IAM tools show the identity has the
role. The result is merged from the whole resource hierarchy; spec holds the enforced rules
and dry_run_spec the audit-only ones.`

const searchIAMPoliciesDescription = `Search the IAM policies of every resource in an organization, folder or project with Cloud Asset Inventory.

Use this to find where a member holds roles anywhere -- including on individual resources
such as buckets, and through bindings to its groups when the query names the group -- or
which identities hold a role or a permission, when checking policies one resource at a time
would miss them. Each result carries only the bindings matching the query.`

const listOrganizationsDescription = `List the GCP organizations the server's identity can see.`

const listFoldersDescription = `List GCP folders: the direct children of an organization or folder, or a search across all visible folders.`

const listProjectsDescription = `List GCP projects: the direct children of an organization or folder, or a search across all visible projects.

Each project comes with its ID, number, display name, parent and labels; to look up known
projects by ID or number, gcp_resolve_project_identifiers is cheaper.`

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

const noQueryMessage = `query must not be empty; pass e.g. 'policy:<member email>' or 'policy:<role>'`

const parentAndQueryMessage = `pass either parent or query, not both`
