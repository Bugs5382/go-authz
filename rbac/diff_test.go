package rbac_test

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import (
	"slices"
	"testing"

	"github.com/Bugs5382/go-authz/rbac"
)

func TestDiff_EqualCatalogsHaveNoDifference(t *testing.T) {
	if d := rbac.Diff(testCatalog(t), testCatalog(t)); len(d) != 0 {
		t.Fatalf("got %v", d)
	}
}

func TestDiff_OrderDoesNotMatter(t *testing.T) {
	a, b := testCatalog(t), testCatalog(t)
	slices.Reverse(b.Permissions)
	slices.Reverse(b.Roles)
	for i := range b.Roles {
		slices.Reverse(b.Roles[i].Permissions)
	}
	slices.Reverse(b.Read.ObfuscateRoles)
	if d := rbac.Diff(a, b); len(d) != 0 {
		t.Fatalf("order is not a difference, got %v", d)
	}
}

func TestDiff_ReportsEveryKindOfChange(t *testing.T) {
	a := testCatalog(t)
	b := testCatalog(t)
	b.Version = 2
	b.BaselineRole = "auditor"
	b.Read.Permission = "audit.read"
	b.Read.SensitivePermission = "user.manage"
	b.Read.ObfuscateRoles = []rbac.Role{"designer"}
	// permissions: remove one, add one, change one
	b.Permissions = slices.DeleteFunc(b.Permissions, func(p rbac.PermissionDef) bool { return p.Name == "template.manage" })
	b.Permissions = append(b.Permissions, rbac.PermissionDef{Name: "report.view"})
	for i := range b.Permissions {
		if b.Permissions[i].Name == "doc.publish" {
			b.Permissions[i].ScopeRole = "editor"
			b.Permissions[i].BypassRoles = []rbac.Role{"superuser"}
		}
		if b.Permissions[i].Name == "doc.write" {
			b.Permissions[i].Scoped = false
		}
	}
	// roles: remove one, add one, change one
	b.Roles = slices.DeleteFunc(b.Roles, func(r rbac.RoleDef) bool { return r.Name == "designer" })
	b.Roles = append(b.Roles, rbac.RoleDef{Name: "manager", Permissions: []rbac.Permission{"doc.read"}})
	for i := range b.Roles {
		if b.Roles[i].Name == "editor" {
			b.Roles[i].Permissions = []rbac.Permission{"doc.read", "audit.read"}
		}
	}
	got := rbac.Diff(a, b)
	want := []string{
		"baselineRole: viewer -> auditor",
		"permission added: report.view",
		"permission changed: doc.publish bypassRoles [] -> [superuser]",
		"permission changed: doc.publish scopeRole reviewer -> editor",
		"permission changed: doc.write scoped true -> false",
		"permission removed: template.manage",
		"read.obfuscateRoles: [superuser] -> [designer]",
		"read.permission: doc.read -> audit.read",
		"read.sensitivePermission: doc.read_sensitive -> user.manage",
		"role added: manager",
		"role changed: editor permissions [doc.read doc.submit doc.write] -> [audit.read doc.read]",
		"role removed: designer",
		"version: 1 -> 2",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}
