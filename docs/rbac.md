# The permission catalog (`rbac`)

`github.com/Bugs5382/go-authz/rbac` is the mechanism for a permission catalog. It names no permission, role
or product. A service supplies the data as a JSON file, embeds it and loads it through the package. The
package does no I/O and keeps no state; the caller loads the subject (roles, grants, overrides) and the
resource (category lineage, assigned users) and passes them in.

`rbac` answers "does this subject hold this permission, in this scope, on this resource". Category rules
(who may read, author or approve in a category tree) are decided by the `ordered` package; `rbac` does not
evaluate them.

## Model

- A **permission** is `<resource>.<verb>`, for example `doc.write`. It may be **scoped**: it takes effect only
  in the categories a subject holds a scoped grant for, and the categories below them.
- A **role** is a named list of permissions. `"*"` in the list means every permission, including ones added to
  the catalog later, except the sensitive read.
- A **baseline role**, if the catalog names one, is held by every subject and is never stored.
- A **scoped grant** (`ScopedGrant{Role, Category}`) gives a role inside one category and everything below it.
  A scoped permission names the **scope role** a grant must carry to confer it.
- **Bypass roles** of a scoped permission hold it in every category without a grant. They still have to hold
  it through the role matrix.
- The **read permission** and the **sensitive-read permission** are named in the catalog. No role holds the
  sensitive read; it is an individual grant (`Subject.ReadSensitive`).
- An **override** pins one resource for one subject: allow always shows it, deny excludes it. **Obfuscate
  roles** still see that an excluded resource exists, but not its content.
- **Break-glass** is a set of resource IDs the subject has an active emergency grant for.

## Catalog JSON

```json
{
  "version": 1,
  "baselineRole": "viewer",
  "read": {
    "permission": "doc.read",
    "sensitivePermission": "doc.read_sensitive",
    "obfuscateRoles": ["superuser"]
  },
  "permissions": [
    { "name": "doc.read" },
    { "name": "doc.read_sensitive" },
    { "name": "doc.write",   "scoped": true, "scopeRole": "editor",   "bypassRoles": ["superuser"] },
    { "name": "doc.publish", "scoped": true, "scopeRole": "reviewer" },
    { "name": "report.view" }
  ],
  "roles": [
    { "name": "viewer",    "permissions": ["doc.read"] },
    { "name": "editor",    "permissions": ["doc.read", "doc.write"] },
    { "name": "reviewer",  "permissions": ["doc.read", "doc.publish"] },
    { "name": "auditor",   "permissions": ["doc.read", "report.view"] },
    { "name": "superuser", "permissions": ["*"] }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | Schema version, `1`. |
| `baselineRole` | no | A role every subject holds. |
| `read.permission` | yes | The permission that means "read a resource". A listed, unscoped permission. |
| `read.sensitivePermission` | yes | The permission that means "read any sensitive resource". Listed, unscoped, different from the read permission, and held by no role. |
| `read.obfuscateRoles` | no | Roles that see an excluded resource obfuscated rather than denied. |
| `permissions[].name` | yes | `<resource>.<verb>`: lower-case letters, digits and `_` around one dot. |
| `permissions[].scoped` | no | The permission needs a scoped grant. |
| `permissions[].scopeRole` | with `scoped` | The role a scoped grant must carry. It must hold the permission. |
| `permissions[].bypassRoles` | no | Roles that hold a scoped permission everywhere. |
| `roles[].name` | yes | Non-empty, no whitespace, no `*`. |
| `roles[].permissions` | yes | Permission names or `"*"`. |

Order is kept: `PermissionNames` and `RoleNames` list them in file order. Unknown fields and data after the
object are rejected. `Parse`, `Load` and `Validate` report every problem at once, in one error coded
`AUTHZ_INVALID_CATALOG`: wrong version; a malformed or duplicate permission or role name; a role listing an
unknown permission, a duplicate, or the sensitive permission; a baseline, scope, bypass or obfuscate role that
does not exist; `scoped` without a `scopeRole`; `scopeRole` or `bypassRoles` on an unscoped permission; a scope
role that does not hold its permission; a missing, unknown, scoped or equal read and sensitive-read permission.

## Authorize

`HasCapability(subject, p)` is true when the baseline role or a held role holds `p`; or `p` is the sensitive
read and the subject has the individual grant; or `p` is scoped and any scoped grant carries a role that holds
`p`. It is the coarse check for work that spans categories.

`Authorize(subject, p, resource)` decides one permission. `resource` is nil for an action not aimed at one
resource. In order, the first rule that applies decides:

1. No capability: deny, `missing_capability`.
2. `p` is scoped. No resource, or no scope in the resource's lineage: deny, `out_of_category_scope`. Otherwise
   allow, `granted`. A bypass role has the scope everywhere; any other subject needs a scoped grant carrying the
   permission's scope role on the resource's category or an ancestor (`CategoryLineage`, or `[Category]` when the
   lineage is empty).
3. `p` is not the read permission, or there is no resource: allow, `granted`.
4. A read of a resource:
   1. override allow: allow, `override_allow`;
   2. override deny: `obfuscate` for an obfuscate role, otherwise deny; both `excluded`;
   3. break-glass for the resource: allow, `break_glass`;
   4. a sensitive resource and no `ReadSensitive`: allow, `assigned` if `UserID` is in `Authors` or `Approvers`,
      otherwise deny, `sensitive`;
   5. otherwise allow, `granted`.

A sensitive resource is therefore read only by the users assigned to it and by explicit grants (the individual
grant, an override allow, break-glass). No role reads it, not even a wildcard role.

### Reasons

| Reason | Meaning |
|---|---|
| `granted` | Allowed through the catalog. |
| `missing_capability` | The subject cannot hold the permission at all. |
| `out_of_category_scope` | A scoped permission, and no scope covers the resource. |
| `override_allow` | An override allow on the resource. |
| `break_glass` | An active break-glass grant on the resource. |
| `excluded` | An override deny on the resource. |
| `sensitive` | A sensitive resource the subject has no grant for. |
| `assigned` | A sensitive resource the subject is assigned to. |

`Decision.Err()` is nil for an allow. Otherwise it is an error coded `AUTHZ_DENIED` that matches `ErrDenied`;
the reason stays in the internal cause and is never put in the wire metadata. A decision with the `obfuscate`
effect is not an allow.

## Errors

| Code | Symbol | Category | Message |
|---|---|---|---|
| 9001 | `AUTHZ_DENIED` | permission-denied | You don't have permission to do that. |
| 9003 | `AUTHZ_UNKNOWN_PERMISSION` | invalid | {permission} is not a known permission. |
| 9004 | `AUTHZ_UNKNOWN_ROLE` | invalid | {role} is not a known role. |
| 9005 | `AUTHZ_INVALID_CATALOG` | invalid | The permission catalog is not valid ({problem}). |

9002 is not used. `rbac.Entries()` returns the go-apperr entries; add them to the registry a service builds at
startup.

## Embedding and refreshing a catalog

Keep the canonical catalog in one place and give every service that needs it an embedded copy:

```go
//go:embed catalog.json
var catalogJSON []byte

var Catalog = rbac.MustParse(catalogJSON) // panics at start-up if the file is invalid
```

`rbac.Diff(a, b)` returns one line per difference between two catalogs (permissions and roles added, removed or
changed, and the read settings), sorted, and empty when they match. Order is not a difference. A service checks
its copy against the canonical one in a test or a task:

```go
func TestCatalogMatchesCanonical(t *testing.T) {
	canonical, err := rbac.Load(canonicalReader(t)) // fetched by the task below
	if err != nil {
		t.Fatal(err)
	}
	if d := rbac.Diff(canonical, Catalog); len(d) != 0 {
		t.Fatalf("embedded catalog differs from the canonical one:\n%s", strings.Join(d, "\n"))
	}
}
```

```yaml
# Taskfile.yaml of the service
catalog:check:
  desc: Fail when the embedded catalog differs from the canonical copy.
  cmds:
    - gh api "repos/<owner>/<repo>/contents/<path>?ref={{.COMMIT}}" -q .content | base64 -d > /tmp/canonical.json
    - CANONICAL_CATALOG=/tmp/canonical.json go test ./... -run TestCatalogMatchesCanonical
```

To refresh, replace the embedded file with the canonical one, run the tests, commit.

## Vectors

`testdata/rbac.json` holds the catalog above and a list of cases: `authorize` (subject, permission, resource,
expected effect and reason), `capability` and `permissionsForRoles`. It is plain data, so a port in another
language can run the same cases. The Go runner decodes it strictly. `task vectors:rbac:refresh REPO=<owner/repo>
COMMIT=<sha> VPATH=<path>` replaces it from a canonical repository and records the source in
`testdata/RBAC_SOURCE`.
