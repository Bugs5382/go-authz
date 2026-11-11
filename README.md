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

## 🗂 Category access

The `categories` package answers "may this person do this action in this category" with the
approved category model, built on the same engine (`Policy` with `DenyOverrides` inside each
category). Subjects are `user:`, `group:` and `role:` strings, a category has a parent chain, and
actions can imply other actions (`manage` implies `author`, `approve` and `read`).

```go
r := categories.New(ruleSet, []categories.Action{
    {ID: "read"},
    {ID: "author", Implies: []string{"read"}},
})
res := r.Resolve(ctx, []string{"user:alice", "group:finance"}, "team", "read")
// res.Allowed, res.Reason ("entry" or "default-deny"), res.DecidedBy
```

The walk goes from the category up its parents. At the nearest category with a matching entry a
Deny beats an Allow, otherwise Allow. `stopInheriting` ends the walk after that category, `*` is
the last stop, and no match is a default deny. The `RuleSet` JSON is the shared wire format
(`{"categories": {...}, "parents": {...}}`).

The model is checked against the shared test vectors in `testdata/decide.json` (source commit in
`testdata/SOURCE`). Refresh them with `task vectors:refresh VECTORS_REPO=../node-raci-editor`.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task ci       # build + vet + test + lint
task lint     # gofmt check + golangci-lint + yamllint
```

## ⚖️ License

MIT © 2026 Shane
