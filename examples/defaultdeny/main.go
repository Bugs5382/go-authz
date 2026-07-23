// Command defaultdeny demonstrates the baseline behaviour of go-authz: a
// Policy with no rules configured denies every request.
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
	// A policy with no rules is a complete, fail-safe default-deny-all
	// authorizer: every request is denied, and the reason says why.
	p := authz.NewPolicy()

	d := p.Decide(context.Background(), authz.Request{
		Subject:  "alice",
		Resource: "report",
		Action:   "read",
	})

	fmt.Printf("allowed=%t effect=%s reason=%s\n", d.Allowed(), d.Effect, d.Reason)
}
