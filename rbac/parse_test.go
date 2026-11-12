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
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Bugs5382/go-apperr"

	"github.com/Bugs5382/go-authz/rbac"
)

func TestParse_Valid(t *testing.T) {
	c, err := rbac.Parse([]byte(catalogJSON))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.BaselineRole != "viewer" || c.Read.Permission != "doc.read" || len(c.Permissions) != 8 || len(c.Roles) != 6 {
		t.Fatalf("unexpected catalog: %+v", c)
	}
}

func TestLoad(t *testing.T) {
	c, err := rbac.Load(strings.NewReader(catalogJSON))
	if err != nil || len(c.Roles) != 6 {
		t.Fatalf("Load = %+v, %v", c, err)
	}
	if _, err := rbac.Load(iotest.ErrReader(errors.New("boom"))); !errors.Is(err, rbac.ErrInvalidCatalog) {
		t.Fatalf("a failed read is an invalid catalog, got %v", err)
	}
}

func TestMustParse(t *testing.T) {
	if c := rbac.MustParse([]byte(catalogJSON)); len(c.Roles) != 6 {
		t.Fatal("MustParse")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse must panic on an invalid catalog")
		}
	}()
	rbac.MustParse([]byte(`{}`))
}

func TestParse_RejectsMalformedInput(t *testing.T) {
	cases := map[string]string{
		"empty":            ``,
		"not json":         `nope`,
		"unknown field":    strings.Replace(catalogJSON, `"version": 1,`, `"version": 1, "extra": true,`, 1),
		"trailing data":    catalogJSON + ` {}`,
		"trailing garbage": catalogJSON + ` x`,
		"wrong type":       `{"version":"one"}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := rbac.Parse([]byte(in))
			if !errors.Is(err, rbac.ErrInvalidCatalog) {
				t.Fatalf("want ErrInvalidCatalog, got %v", err)
			}
			if code, ok := apperr.Code(err); !ok || code != rbac.CodeInvalidCatalog {
				t.Fatalf("want code %d, got %d (%v)", rbac.CodeInvalidCatalog, code, ok)
			}
		})
	}
}

// mutate parses the test catalog JSON, applies a textual replacement and
// returns the validation error.
func invalid(t *testing.T, old, repl string) error {
	t.Helper()
	if !strings.Contains(catalogJSON, old) {
		t.Fatalf("test setup: %q not in the catalog", old)
	}
	_, err := rbac.Parse([]byte(strings.Replace(catalogJSON, old, repl, 1)))
	if err == nil {
		t.Fatalf("replacing %q with %q must be invalid", old, repl)
	}
	if !errors.Is(err, rbac.ErrInvalidCatalog) {
		t.Fatalf("want ErrInvalidCatalog, got %v", err)
	}
	return err
}

func TestValidate_Problems(t *testing.T) {
	cases := []struct {
		name, old, repl, problem string
	}{
		{"version", `"version": 1`, `"version": 2`, "version"},
		{"permission name without a dot", `{ "name": "audit.read" }`, `{ "name": "audit" }`, "not <resource>.<verb>"},
		{"permission name upper case", `{ "name": "audit.read" }`, `{ "name": "Audit.read" }`, "not <resource>.<verb>"},
		{"permission name two dots", `{ "name": "audit.read" }`, `{ "name": "a.b.c" }`, "not <resource>.<verb>"},
		{"duplicate permission", `{ "name": "user.manage" }`, `{ "name": "audit.read" }`, "duplicate permission"},
		{"empty role name", `{ "name": "viewer",    "permissions"`, `{ "name": "",    "permissions"`, "role name"},
		{"wildcard role name", `{ "name": "viewer",    "permissions"`, `{ "name": "*",    "permissions"`, "role name"},
		{"space in role name", `{ "name": "viewer",    "permissions"`, `{ "name": "a b",    "permissions"`, "role name"},
		{"duplicate role", `{ "name": "auditor",   "permissions"`, `{ "name": "viewer",   "permissions"`, "duplicate role"},
		{"unknown permission in a role", `["doc.read", "audit.read"]`, `["doc.read", "audit.nope"]`, "unknown permission"},
		{"duplicate entry in a role", `["doc.read", "audit.read"]`, `["doc.read", "doc.read"]`, "lists doc.read twice"},
		{"role lists the sensitive permission", `["doc.read", "audit.read"]`, `["doc.read", "doc.read_sensitive"]`, "sensitive"},
		{"unknown baseline role", `"baselineRole": "viewer"`, `"baselineRole": "ghost"`, "baselineRole"},
		{"unknown scope role", `"scopeRole": "reviewer"`, `"scopeRole": "ghost"`, "scopeRole"},
		{"unknown bypass role", `"bypassRoles": ["superuser"] },
    { "name": "doc.submit"`, `"bypassRoles": ["ghost"] },
    { "name": "doc.submit"`, "bypassRoles"},
		{"unknown obfuscate role", `"obfuscateRoles": ["superuser"]`, `"obfuscateRoles": ["ghost"]`, "obfuscateRoles"},
		{"scoped without a scope role", `"scoped": true, "scopeRole": "reviewer"`, `"scoped": true`, "needs a scopeRole"},
		{"scope role on an unscoped permission", `{ "name": "audit.read" }`, `{ "name": "audit.read", "scopeRole": "auditor" }`, "not scoped"},
		{"bypass roles on an unscoped permission", `{ "name": "audit.read" }`, `{ "name": "audit.read", "bypassRoles": ["superuser"] }`, "not scoped"},
		{"scope role that does not hold the permission", `"scopeRole": "reviewer"`, `"scopeRole": "auditor"`, "does not hold"},
		{"missing read permission", `"permission": "doc.read",`, ``, "read.permission"},
		{"unknown read permission", `"permission": "doc.read",`, `"permission": "doc.nope",`, "read.permission"},
		{"scoped read permission", `"permission": "doc.read",`, `"permission": "doc.write",`, "read.permission"},
		{"missing sensitive permission", `"sensitivePermission": "doc.read_sensitive",`, ``, "sensitivePermission"},
		{"unknown sensitive permission", `"sensitivePermission": "doc.read_sensitive"`, `"sensitivePermission": "doc.nope"`, "sensitivePermission"},
		{"scoped sensitive permission", `"sensitivePermission": "doc.read_sensitive"`, `"sensitivePermission": "doc.write"`, "sensitivePermission"},
		{"sensitive equals read", `"sensitivePermission": "doc.read_sensitive"`, `"sensitivePermission": "doc.read"`, "differ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := invalid(t, tc.old, tc.repl)
			if !strings.Contains(err.Error(), tc.problem) {
				t.Fatalf("error %q should mention %q", err, tc.problem)
			}
			if got := apperr.Metadata(err)["problem"]; !strings.Contains(got, tc.problem) {
				t.Fatalf("problem metadata %q should mention %q", got, tc.problem)
			}
		})
	}
}

func TestValidate_ReportsEveryProblem(t *testing.T) {
	c := testCatalog(t)
	c.Version = 9
	c.BaselineRole = "ghost"
	c.Permissions = append(c.Permissions, rbac.PermissionDef{Name: "bad"})
	err := c.Validate()
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"version", "baselineRole", "<resource>.<verb>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestValidate_ZeroCatalogIsInvalid(t *testing.T) {
	if err := (rbac.Catalog{}).Validate(); !errors.Is(err, rbac.ErrInvalidCatalog) {
		t.Fatalf("got %v", err)
	}
}

func TestValidate_BaselineAndObfuscateAreOptional(t *testing.T) {
	c := testCatalog(t)
	c.BaselineRole = ""
	c.Read.ObfuscateRoles = nil
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_ValidCatalogReturnsNil(t *testing.T) {
	if err := testCatalog(t).Validate(); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(catalogJSON))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(strings.Replace(catalogJSON, `"*"`, `"doc.read_sensitive"`, 1)))
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := rbac.Parse(in)
		if err != nil {
			if !errors.Is(err, rbac.ErrInvalidCatalog) {
				t.Fatalf("an error must be an invalid catalog: %v", err)
			}
			return
		}
		// A catalog that parses must revalidate and never panic when used.
		if err := c.Validate(); err != nil {
			t.Fatalf("a parsed catalog must validate: %v", err)
		}
		for _, p := range c.Permissions {
			for _, r := range c.Roles {
				c.RoleHolds(r.Name, p.Name)
			}
			c.Authorize(rbac.Subject{UserID: "u", Roles: []rbac.Role{c.BaselineRole}}, p.Name, &rbac.Resource{ID: "r", Sensitive: true})
		}
		for _, r := range c.Roles {
			for _, p := range c.RolePermissions(r.Name) {
				if p == c.Read.SensitivePermission {
					t.Fatalf("role %q holds the sensitive permission", r.Name)
				}
			}
		}
		if d := rbac.Diff(c, c); len(d) != 0 {
			t.Fatalf("a catalog differs from itself: %v", d)
		}
	})
}
