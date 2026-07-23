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

// RBAC is a role-based rule: subjects are assigned roles, and roles are granted
// (resource, action) permissions. It is applicable and yields Allow when one of
// the request subject's roles grants the requested resource and action;
// otherwise it is inapplicable (it never denies). Pair it with a Deny default
// so ungranted requests fall through to denial.
//
// Grants may use Wildcard ("*") for the resource and/or action to grant all
// values of that dimension. RBAC is a Rule.
type RBAC struct {
	id     string
	roles  map[string][]string // subject -> roles
	grants map[string][]grant  // role -> grants
}

type grant struct {
	resource string
	action   string
}

// NewRBAC returns an empty RBAC rule with the given id.
func NewRBAC(id string) *RBAC {
	return &RBAC{id: id, roles: map[string][]string{}, grants: map[string][]grant{}}
}

// Assign gives a subject one or more roles and returns the RBAC for chaining.
func (r *RBAC) Assign(subject string, roles ...string) *RBAC {
	r.roles[subject] = append(r.roles[subject], roles...)
	return r
}

// Grant permits a role to perform action on resource (either may be Wildcard)
// and returns the RBAC for chaining.
func (r *RBAC) Grant(role, resource, action string) *RBAC {
	r.grants[role] = append(r.grants[role], grant{resource: resource, action: action})
	return r
}

// ID returns the rule identifier.
func (r *RBAC) ID() string { return r.id }

// Eval reports Allow (applicable) when a role of req.Subject grants the request.
func (r *RBAC) Eval(_ context.Context, req Request) (Effect, bool) {
	for _, role := range r.roles[req.Subject] {
		for _, g := range r.grants[role] {
			if dimMatch(g.resource, req.Resource) && dimMatch(g.action, req.Action) {
				return Allow, true
			}
		}
	}
	return Deny, false
}

// dimMatch reports whether a configured dimension value (possibly Wildcard)
// matches a request value.
func dimMatch(configured, actual string) bool {
	return configured == Wildcard || configured == actual
}

var _ Rule = (*RBAC)(nil)
