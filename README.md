# go-authz 🔐

> A small, dependency-free, general-purpose **authorization engine** for Go. You configure the model; the library provides the decisions. Nothing is hard-coded to one scheme.

## 📦 Install

```bash
go get github.com/Bugs5382/go-authz
```

## ✨ What you get

- **default-deny-all** baseline — fail-safe by construction (`Deny` is the zero value).
- **allow / RBAC-style** rules — subjects hold roles, roles are granted permissions.
- **responsibility matrix** — a `subject × resource × action` table with wildcards.
- Framework-agnostic: it returns `Decision`s. No HTTP/gRPC middleware baked in — you wire it.
- Zero third-party dependencies. Optional decision logging via the standard library `log/slog`.

## 🚀 Usage

Every configuration runs on the same engine: build a `Policy`, add `Rule`s, call `Decide`.

### Default-deny

```go
p := authz.NewPolicy() // no rules
d := p.Decide(ctx, authz.Request{Subject: "alice", Resource: "report", Action: "read"})
// d.Allowed() == false, d.Reason == authz.ReasonNoMatch
```

### Allow / RBAC-style

```go
rbac := authz.NewRBAC("rbac").
    Assign("alice", "editor").
    Grant("editor", authz.Wildcard, "write") // editors write any resource

p := authz.NewPolicy().Add(rbac) // deny-by-default + grants
p.Decide(ctx, authz.Request{Subject: "alice", Resource: "post", Action: "write"}).Allowed() // true
```

### Responsibility matrix

Map your own actions (view / edit / delete, …) onto the action dimension:

```go
m := authz.NewMatrix("access").
    Allow(authz.Wildcard, "document", "view").
    Allow("editor1", "document", "edit").
    Deny("editor1", "document", "delete").      // editor1 may not delete
    Allow("admin1", "document", "delete")

p := authz.NewPolicy().Add(m)
p.Decide(ctx, authz.Request{Subject: "editor1", Resource: "document", Action: "delete"}).Allowed() // false
```

## 🧭 Decisions

`Decide` returns a `Decision{Effect, Reason, RuleID}`. `Reason` is a stable machine-readable code
(`rule_matched` or `no_matching_rule`) and `RuleID` names the deciding rule — ready for
auth-decision logging downstream.

## 🔀 Combining algorithms

`FirstApplicable` (default), `DenyOverrides`, and `AllowOverrides` are built in; supply your own via
`WithCombiner`. Set the fallthrough with `WithDefaultEffect` (defaults to `Deny`).

## 🔥 Ordered model

The `ordered` package (`github.com/Bugs5382/go-authz/ordered`) is a firewall-style access model, separate
from the root package. A rule set has categories (with a parent chain); each category holds rows, one per
subject (`user:`, `group:`, `role:`, `everyone:*`), with one allow/deny cell per action (`read`, `author`,
`approve`, `manage`, `ack`). The decision is made per action, top-down: the first row that matches the
person and has a cell for that action decides, and an empty cell is skipped. A child's own rows come
before the inherited ones, and the default is deny.

```go
rs := ordered.RuleSet{
    Categories: map[string]ordered.Category{
        "policies": {Owners: []string{"user:erin"}, Entries: []ordered.Entry{
            {Subject: "user:ann", Action: "approve", Effect: ordered.Deny},
            {Subject: "group:finance", Action: "approve", Effect: ordered.Allow},
        }},
    },
    Parents: map[string]string{"security-policy": "policies"},
}
dave := ordered.Person{ID: "dave", Groups: []string{"finance"}}
d := ordered.Decide(rs, dave, "security-policy", "approve") // d.Allowed, d.Reason, d.DecidedBy
pool := ordered.Pool(rs, people, "security-policy", "approve") // owners first, then who a row allows
```

- Owners always have read, author, approve and manage (never ack), immune to a deny, inherited down.
- An allowed author, approve or manage gives read, even over a read deny; manage also gives author.
- `ack` requires `read`: a read deny turns it off (`Reason == "requires"`, `GatedBy == "read"`).
- A superuser seat (`Model.Superusers`, for example `role:root`) is exempt for the actions it lists; a deny
  that would have applied is ignored and reported as `Decision.ConfiguredBlock`.
- `stopInheriting` is ignored by this model.

`ordered.Decide` and `ordered.Pool` use `ordered.DefaultModel()`; build an `ordered.Model` to change the
actions, owner kinds or superusers. The behaviour is pinned by the shared vectors in `testdata/ordered.json`
(source commit in `testdata/SOURCE`); refresh with `task vectors:refresh COMMIT=<sha>`.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task ci       # build + vet + test + lint
task lint     # gofmt check + golangci-lint + yamllint
```

## ⚖️ License

MIT © 2026 Shane
