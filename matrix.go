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

// Matrix is a responsibility matrix: a subject x resource x action table that
// resolves to an Effect. An application maps its own relations (for example
// view, edit, delete) onto the action dimension.
//
// Any dimension of an entry may be Wildcard ("*"). Lookup is most-specific
// wins: an entry with more exact (non-wildcard) dimensions takes precedence,
// and ties are broken in subject, then resource, then action order. The Matrix
// is applicable only when some entry matches; otherwise the request falls
// through to the policy default. The Matrix is a Rule.
type Matrix struct {
	id      string
	entries map[cell]Effect
}

type cell struct {
	subject  string
	resource string
	action   string
}

// NewMatrix returns an empty Matrix with the given id.
func NewMatrix(id string) *Matrix {
	return &Matrix{id: id, entries: map[cell]Effect{}}
}

// Set records effect for the subject/resource/action cell (any may be Wildcard)
// and returns the Matrix for chaining.
func (m *Matrix) Set(subject, resource, action string, effect Effect) *Matrix {
	m.entries[cell{subject, resource, action}] = effect
	return m
}

// Allow records an Allow cell. It is shorthand for Set(..., Allow).
func (m *Matrix) Allow(subject, resource, action string) *Matrix {
	return m.Set(subject, resource, action, Allow)
}

// Deny records a Deny cell. It is shorthand for Set(..., Deny).
func (m *Matrix) Deny(subject, resource, action string) *Matrix {
	return m.Set(subject, resource, action, Deny)
}

// ID returns the rule identifier.
func (m *Matrix) ID() string { return m.id }

// precedence lists the (subjectExact, resourceExact, actionExact) masks from
// most to least specific; ties favour subject, then resource, then action.
var precedence = [8][3]bool{
	{true, true, true},
	{true, true, false},
	{true, false, true},
	{false, true, true},
	{true, false, false},
	{false, true, false},
	{false, false, true},
	{false, false, false},
}

// Eval returns the effect of the most specific matching cell, if any.
func (m *Matrix) Eval(_ context.Context, req Request) (Effect, bool) {
	for _, mask := range precedence {
		key := cell{
			subject:  dimKey(mask[0], req.Subject),
			resource: dimKey(mask[1], req.Resource),
			action:   dimKey(mask[2], req.Action),
		}
		if e, ok := m.entries[key]; ok {
			return e, true
		}
	}
	return Deny, false
}

func dimKey(exact bool, actual string) string {
	if exact {
		return actual
	}
	return Wildcard
}

var _ Rule = (*Matrix)(nil)
