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

// MatchFunc reports whether a rule applies to req. It backs the functional
// rule constructors and the composable matchers.
type MatchFunc func(ctx context.Context, req Request) bool

type funcRule struct {
	id     string
	effect Effect
	match  MatchFunc
}

func (r funcRule) ID() string { return r.id }

func (r funcRule) Eval(ctx context.Context, req Request) (Effect, bool) {
	if r.match == nil || !r.match(ctx, req) {
		return Deny, false
	}
	return r.effect, true
}

// NewRule returns a rule with the given id that yields effect when match
// reports true, and is inapplicable otherwise.
func NewRule(id string, effect Effect, match MatchFunc) Rule {
	return funcRule{id: id, effect: effect, match: match}
}

// AllowWhen returns a rule that allows when match reports true.
func AllowWhen(id string, match MatchFunc) Rule { return NewRule(id, Allow, match) }

// DenyWhen returns a rule that denies when match reports true.
func DenyWhen(id string, match MatchFunc) Rule { return NewRule(id, Deny, match) }

// SubjectIs matches requests whose Subject equals s.
func SubjectIs(s string) MatchFunc {
	return func(_ context.Context, req Request) bool { return req.Subject == s }
}

// ResourceIs matches requests whose Resource equals r.
func ResourceIs(r string) MatchFunc {
	return func(_ context.Context, req Request) bool { return req.Resource == r }
}

// ActionIs matches requests whose Action equals a.
func ActionIs(a string) MatchFunc {
	return func(_ context.Context, req Request) bool { return req.Action == a }
}

// All matches when every provided matcher matches (logical AND). With no
// matchers it matches everything.
func All(ms ...MatchFunc) MatchFunc {
	return func(ctx context.Context, req Request) bool {
		for _, m := range ms {
			if !m(ctx, req) {
				return false
			}
		}
		return true
	}
}

// Any matches when at least one provided matcher matches (logical OR). With no
// matchers it matches nothing.
func Any(ms ...MatchFunc) MatchFunc {
	return func(ctx context.Context, req Request) bool {
		for _, m := range ms {
			if m(ctx, req) {
				return true
			}
		}
		return false
	}
}
