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

// Request describes an access attempt: a Subject trying to perform an Action on
// a Resource. Subject, Resource, and Action are opaque strings whose meaning is
// defined entirely by the consuming application.
//
// Attributes carries optional context for attribute-based rules (for example
// ownership, tenant, or a relation such as owner/reviewer). It may be nil.
type Request struct {
	Subject    string
	Resource   string
	Action     string
	Attributes map[string]any
}

// Attr returns the attribute stored under key and whether it was present.
func (r Request) Attr(key string) (any, bool) {
	v, ok := r.Attributes[key]
	return v, ok
}

// Evaluator decides authorization Requests. Policy is the built-in
// implementation; the interface lets applications depend on the behaviour
// rather than the concrete type.
type Evaluator interface {
	Decide(ctx context.Context, req Request) Decision
}
