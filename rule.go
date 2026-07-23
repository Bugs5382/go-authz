package authz

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

import "context"

// Wildcard is the token that matches any value in an RBAC grant or a Matrix
// entry. An application that needs "*" to be a literal subject, resource, or
// action should not use RBAC/Matrix wildcards for that dimension.
const Wildcard = "*"

// Rule is a single element of a Policy.
//
// Eval reports whether the rule is applicable to req; when it is (matched
// true), the returned Effect is the rule's verdict. When matched is false the
// Effect is ignored and the rule takes no part in the decision.
type Rule interface {
	// ID is a stable identifier used as the Decision's RuleID.
	ID() string
	// Eval decides whether the rule applies and, if so, with what effect.
	Eval(ctx context.Context, req Request) (effect Effect, matched bool)
}
