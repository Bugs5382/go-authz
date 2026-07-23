# Examples 📂

Runnable programs demonstrating go-authz. Each is a standalone `package main`;
run any of them with `go run ./examples/<name>`.

- `defaultdeny` - a policy with no rules; every request is denied.
- `rbac` - subjects hold roles, roles are granted permissions.
- `matrix` - a responsibility matrix: a subject x resource x action table
  with wildcards, deny cells, and most-specific-wins precedence.
