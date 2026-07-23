// Command matrix demonstrates go-authz's responsibility matrix: a subject x
// resource x action table with per-dimension wildcards and
// most-specific-wins precedence.
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
	m := authz.NewMatrix("access").
		Allow(authz.Wildcard, "document", "view"). // anyone may view a document
		Allow("editor1", "document", "edit").      // editor1 may edit
		Deny("editor1", "document", "delete").     // but may not delete
		Allow("admin1", "document", "delete")      // admin1 may delete

	p := authz.NewPolicy().Add(m)
	ctx := context.Background()

	cases := []authz.Request{
		{Subject: "anyone", Resource: "document", Action: "view"},
		{Subject: "editor1", Resource: "document", Action: "edit"},
		{Subject: "editor1", Resource: "document", Action: "delete"},
		{Subject: "admin1", Resource: "document", Action: "delete"},
	}

	for _, req := range cases {
		d := p.Decide(ctx, req)
		fmt.Printf("%s %s %s: allowed=%t\n", req.Subject, req.Action, req.Resource, d.Allowed())
	}
}
