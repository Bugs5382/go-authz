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
	"testing"

	"github.com/Bugs5382/go-authz/rbac"
)

// catalogJSON is a neutral catalog used by the tests. It has the same shape as
// any real one: a baseline role, scoped permissions with a scope role, a role
// that bypasses scope for authoring but not for publishing, and a wildcard role.
const catalogJSON = `{
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
    { "name": "doc.submit",  "scoped": true, "scopeRole": "editor",   "bypassRoles": ["superuser"] },
    { "name": "doc.publish", "scoped": true, "scopeRole": "reviewer" },
    { "name": "template.manage" },
    { "name": "audit.read" },
    { "name": "user.manage" }
  ],
  "roles": [
    { "name": "viewer",    "permissions": ["doc.read"] },
    { "name": "editor",    "permissions": ["doc.read", "doc.write", "doc.submit"] },
    { "name": "reviewer",  "permissions": ["doc.read", "doc.publish"] },
    { "name": "designer",  "permissions": ["doc.read", "template.manage"] },
    { "name": "auditor",   "permissions": ["doc.read", "audit.read"] },
    { "name": "superuser", "permissions": ["*"] }
  ]
}`

func testCatalog(t testing.TB) rbac.Catalog {
	t.Helper()
	c, err := rbac.Parse([]byte(catalogJSON))
	if err != nil {
		t.Fatalf("the test catalog must parse: %v", err)
	}
	return c
}

func roles(rs ...rbac.Role) rbac.Subject { return rbac.Subject{Roles: rs} }
