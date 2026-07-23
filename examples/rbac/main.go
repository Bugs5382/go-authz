// Command rbac demonstrates go-authz's RBAC rule: subjects are assigned
// roles, and roles are granted (resource, action) permissions.
package main

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

func main() {
	rbac := authz.NewRBAC("rbac").
		Assign("alice", "editor").
		Assign("bob", "viewer").
		Grant("editor", authz.Wildcard, "write"). // editors write any resource
		Grant("viewer", "report", "read")         // viewers read the report

	// A Deny default (the Policy default) means anything not granted falls
	// through to denial.
	p := authz.NewPolicy().Add(rbac)
	ctx := context.Background()

	alice := p.Decide(ctx, authz.Request{Subject: "alice", Resource: "post", Action: "write"})
	bob := p.Decide(ctx, authz.Request{Subject: "bob", Resource: "post", Action: "write"})

	fmt.Printf("alice write post: allowed=%t reason=%s\n", alice.Allowed(), alice.Reason)
	fmt.Printf("bob write post:   allowed=%t reason=%s\n", bob.Allowed(), bob.Reason)
}
