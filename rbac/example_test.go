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
	"fmt"

	"github.com/Bugs5382/go-authz/rbac"
)

// A service keeps its catalog in a JSON file, embeds it and loads it once at
// startup. Here the catalog is a string to keep the example self-contained.
const exampleCatalog = `{
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
    { "name": "doc.write", "scoped": true, "scopeRole": "editor", "bypassRoles": ["superuser"] },
    { "name": "doc.publish", "scoped": true, "scopeRole": "reviewer" }
  ],
  "roles": [
    { "name": "viewer", "permissions": ["doc.read"] },
    { "name": "editor", "permissions": ["doc.read", "doc.write"] },
    { "name": "reviewer", "permissions": ["doc.read", "doc.publish"] },
    { "name": "superuser", "permissions": ["*"] }
  ]
}`

func ExampleCatalog_Authorize() {
	cat, err := rbac.Parse([]byte(exampleCatalog))
	if err != nil {
		fmt.Println(err)
		return
	}
	bob := rbac.Subject{
		UserID:       "bob",
		Roles:        []rbac.Role{"editor"},
		ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Workplace"}},
	}
	doc := &rbac.Resource{ID: "DOC-1", Category: "Facilities", CategoryLineage: []string{"Facilities", "Workplace"}}
	fmt.Println(cat.Authorize(bob, "doc.write", doc).Effect)
	fmt.Println(cat.Authorize(bob, "doc.publish", doc).Reason)
	// Output:
	// allow
	// missing_capability
}

func ExampleCatalog_Authorize_sensitive() {
	cat := rbac.MustParse([]byte(exampleCatalog))
	doc := &rbac.Resource{ID: "DOC-2", Sensitive: true, Authors: []string{"bob"}}
	fmt.Println(cat.Authorize(rbac.Subject{UserID: "bob"}, "doc.read", doc).Reason)
	fmt.Println(cat.Authorize(rbac.Subject{UserID: "alice", Roles: []rbac.Role{"superuser"}}, "doc.read", doc).Reason)
	// Output:
	// assigned
	// sensitive
}

func ExampleDecision_Err() {
	cat := rbac.MustParse([]byte(exampleCatalog))
	d := cat.Authorize(rbac.Subject{UserID: "eve"}, "doc.write", nil)
	fmt.Println(d.Reason, errors.Is(d.Err(), rbac.ErrDenied))
	// Output:
	// missing_capability true
}

func ExampleDiff() {
	canonical := rbac.MustParse([]byte(exampleCatalog))
	embedded := rbac.MustParse([]byte(exampleCatalog))
	embedded.Roles[0].Permissions = []rbac.Permission{"doc.read", "doc.write"}
	for _, line := range rbac.Diff(canonical, embedded) {
		fmt.Println(line)
	}
	// Output:
	// role changed: viewer permissions [doc.read] -> [doc.read doc.write]
}
