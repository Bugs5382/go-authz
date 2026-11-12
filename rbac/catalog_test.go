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
	"errors"
	"slices"
	"testing"

	"github.com/Bugs5382/go-apperr"

	"github.com/Bugs5382/go-authz/rbac"
)

func TestRolePermissions(t *testing.T) {
	c := testCatalog(t)
	cases := []struct {
		role rbac.Role
		want []rbac.Permission
	}{
		{"viewer", []rbac.Permission{"doc.read"}},
		{"editor", []rbac.Permission{"doc.read", "doc.write", "doc.submit"}},
		{"reviewer", []rbac.Permission{"doc.read", "doc.publish"}},
		{"designer", []rbac.Permission{"doc.read", "template.manage"}},
		{"auditor", []rbac.Permission{"doc.read", "audit.read"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			if got := c.RolePermissions(tc.role); !slices.Equal(got, tc.want) {
				t.Errorf("role %q: got %v, want %v", tc.role, got, tc.want)
			}
		})
	}
}

func TestRolePermissions_WildcardHoldsTheCatalogButTheSensitiveRead(t *testing.T) {
	c := testCatalog(t)
	got := c.RolePermissions("superuser")
	for _, p := range c.PermissionNames() {
		if p == "doc.read_sensitive" {
			if slices.Contains(got, p) {
				t.Errorf("a wildcard role must not hold %q", p)
			}
			continue
		}
		if !slices.Contains(got, p) {
			t.Errorf("superuser missing %q", p)
		}
	}
	if len(got) != len(c.PermissionNames())-1 {
		t.Errorf("superuser holds %d, want %d", len(got), len(c.PermissionNames())-1)
	}
}

func TestRolePermissions_UnknownRoleHoldsNothing(t *testing.T) {
	if got := testCatalog(t).RolePermissions("admin"); len(got) != 0 {
		t.Fatalf("an unknown role must hold nothing, got %v", got)
	}
}

func TestPermissionsForRoles_AddsTheBaseline(t *testing.T) {
	c := testCatalog(t)
	if got := c.PermissionsForRoles(); !slices.Equal(got, []rbac.Permission{"doc.read"}) {
		t.Fatalf("no roles still hold the baseline, got %v", got)
	}
	if got := c.PermissionsForRoles("admin"); !slices.Equal(got, []rbac.Permission{"doc.read"}) {
		t.Fatalf("an unknown role adds nothing, got %v", got)
	}
	got := c.PermissionsForRoles("auditor", "reviewer")
	// catalog order, not argument order
	want := []rbac.Permission{"doc.read", "doc.publish", "audit.read"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPermissionsForRoles_NoBaselineRole(t *testing.T) {
	c := testCatalog(t)
	c.BaselineRole = ""
	if got := c.PermissionsForRoles(); len(got) != 0 {
		t.Fatalf("with no baseline role nothing is held implicitly, got %v", got)
	}
}

func TestCatalogSnapshot(t *testing.T) {
	c := testCatalog(t)
	wantP := []rbac.Permission{
		"doc.read", "doc.read_sensitive", "doc.write", "doc.submit", "doc.publish",
		"template.manage", "audit.read", "user.manage",
	}
	if got := c.PermissionNames(); !slices.Equal(got, wantP) {
		t.Fatalf("permissions: got %v want %v", got, wantP)
	}
	wantR := []rbac.Role{"viewer", "editor", "reviewer", "designer", "auditor", "superuser"}
	if got := c.RoleNames(); !slices.Equal(got, wantR) {
		t.Fatalf("roles: got %v want %v", got, wantR)
	}
	counts := map[rbac.Role]int{"viewer": 1, "editor": 3, "reviewer": 2, "designer": 2, "auditor": 2, "superuser": len(wantP) - 1}
	for r, n := range counts {
		if got := len(c.RolePermissions(r)); got != n {
			t.Errorf("role %q holds %d, want %d", r, got, n)
		}
	}
}

func TestCatalog_AccessorsReturnCopies(t *testing.T) {
	c := testCatalog(t)
	c.PermissionNames()[0] = "mutated.name"
	c.RoleNames()[0] = "mutated"
	if c.PermissionNames()[0] != "doc.read" || c.RoleNames()[0] != "viewer" {
		t.Fatal("mutating a returned slice must not change the catalog")
	}
}

func TestPermission_Parts(t *testing.T) {
	p := rbac.Permission("doc.read_sensitive")
	if p.Resource() != "doc" || p.Verb() != "read_sensitive" {
		t.Fatalf("parts of %q = %q, %q", p, p.Resource(), p.Verb())
	}
	if q := rbac.Permission("nodot"); q.Resource() != "nodot" || q.Verb() != "" {
		t.Fatalf("parts of %q = %q, %q", q, q.Resource(), q.Verb())
	}
}

func TestIsScoped(t *testing.T) {
	c := testCatalog(t)
	for _, p := range c.PermissionNames() {
		want := p == "doc.write" || p == "doc.submit" || p == "doc.publish"
		if got := c.IsScoped(p); got != want {
			t.Errorf("%q scoped = %v, want %v", p, got, want)
		}
	}
	if c.IsScoped("report.export") {
		t.Error("a permission outside the catalog is not scoped")
	}
}

func TestRoleHolds(t *testing.T) {
	c := testCatalog(t)
	if !c.RoleHolds("superuser", "report.export") {
		t.Error("a wildcard role holds a permission not yet in the catalog")
	}
	if c.RoleHolds("auditor", "report.export") {
		t.Error("a non-wildcard role must not hold a permission outside its grants")
	}
	if c.RoleHolds("superuser", "doc.read_sensitive") {
		t.Error("the wildcard must not cover the sensitive read")
	}
	if c.RoleHolds("nobody", "doc.read") {
		t.Error("an unknown role holds nothing")
	}
}

func TestHasCapability_WildcardCoversPermissionsAddedLater(t *testing.T) {
	c := testCatalog(t)
	if !c.HasCapability(roles("superuser"), "report.export") {
		t.Fatal("superuser holds every capability, including ones not yet in the catalog")
	}
	if c.HasCapability(roles("auditor"), "report.export") {
		t.Fatal("a non-wildcard role must not hold a permission outside its grants")
	}
}

func TestParsePermission(t *testing.T) {
	c := testCatalog(t)
	p, err := c.ParsePermission("audit.read")
	if err != nil || p != "audit.read" {
		t.Fatalf("ParsePermission(audit.read) = %q, %v", p, err)
	}
	_, err = c.ParsePermission("doc.delete")
	if !errors.Is(err, rbac.ErrUnknownPermission) {
		t.Fatalf("want ErrUnknownPermission, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeUnknownPermission {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeUnknownPermission, code, ok)
	}
	if got := apperr.Metadata(err)["permission"]; got != "doc.delete" {
		t.Fatalf("want permission metadata, got %q", got)
	}
}

func TestParseRole(t *testing.T) {
	c := testCatalog(t)
	r, err := c.ParseRole("designer")
	if err != nil || r != "designer" {
		t.Fatalf("ParseRole(designer) = %q, %v", r, err)
	}
	_, err = c.ParseRole("admin")
	if !errors.Is(err, rbac.ErrUnknownRole) {
		t.Fatalf("a role outside the catalog must not parse, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeUnknownRole {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeUnknownRole, code, ok)
	}
	if got := apperr.Metadata(err)["role"]; got != "admin" {
		t.Fatalf("want role metadata, got %q", got)
	}
}

func TestNoRoleGrantsTheSensitiveRead(t *testing.T) {
	c := testCatalog(t)
	for _, r := range c.RoleNames() {
		if slices.Contains(c.RolePermissions(r), "doc.read_sensitive") {
			t.Errorf("role %q grants the sensitive read; it is an individual grant only", r)
		}
		if c.HasCapability(roles(r), "doc.read_sensitive") {
			t.Errorf("role %q holds the sensitive-read capability", r)
		}
	}
}
