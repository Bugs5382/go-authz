package authz_test

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
	"context"
	"fmt"

	authz "github.com/Bugs5382/go-authz"
)

// Example_defaultDeny shows the baseline: a policy with no rules denies every
// request.
func Example_defaultDeny() {
	p := authz.NewPolicy()

	d := p.Decide(context.Background(), authz.Request{
		Subject:  "alice",
		Resource: "report",
		Action:   "read",
	})

	fmt.Printf("allowed=%t effect=%s reason=%s\n", d.Allowed(), d.Effect, d.Reason)
	// Output: allowed=false effect=deny reason=no_matching_rule
}

// Example_rbac shows an allow/RBAC-style configuration: subjects hold roles and
// roles are granted permissions, on top of a deny-by-default policy.
func Example_rbac() {
	rbac := authz.NewRBAC("rbac").
		Assign("alice", "editor").
		Assign("bob", "viewer").
		Grant("editor", authz.Wildcard, "write"). // editors write any resource
		Grant("viewer", "report", "read")         // viewers read the report

	p := authz.NewPolicy().Add(rbac)
	ctx := context.Background()

	alice := p.Decide(ctx, authz.Request{Subject: "alice", Resource: "post", Action: "write"})
	bob := p.Decide(ctx, authz.Request{Subject: "bob", Resource: "post", Action: "write"})

	fmt.Printf("alice write post: %t\n", alice.Allowed())
	fmt.Printf("bob write post:   %t\n", bob.Allowed())
	// Output:
	// alice write post: true
	// bob write post:   false
}

// Example_matrix shows a responsibility-matrix configuration. The application
// maps its own actions onto the action dimension: here view, edit, and delete.
// Deny cells and wildcards compose, most-specific wins.
func Example_matrix() {
	m := authz.NewMatrix("access").
		Allow(authz.Wildcard, "document", "view"). // anyone may view a document
		Allow("editor1", "document", "edit").      // editor1 may edit
		Deny("editor1", "document", "delete").     // but may not delete
		Allow("admin1", "document", "delete")      // admin1 may delete

	p := authz.NewPolicy().Add(m)
	ctx := context.Background()

	fmt.Printf("anyone view:    %t\n", p.Decide(ctx, authz.Request{Subject: "x", Resource: "document", Action: "view"}).Allowed())
	fmt.Printf("editor1 edit:   %t\n", p.Decide(ctx, authz.Request{Subject: "editor1", Resource: "document", Action: "edit"}).Allowed())
	fmt.Printf("editor1 delete: %t\n", p.Decide(ctx, authz.Request{Subject: "editor1", Resource: "document", Action: "delete"}).Allowed())
	fmt.Printf("admin1 delete:  %t\n", p.Decide(ctx, authz.Request{Subject: "admin1", Resource: "document", Action: "delete"}).Allowed())
	// Output:
	// anyone view:    true
	// editor1 edit:   true
	// editor1 delete: false
	// admin1 delete:  true
}
