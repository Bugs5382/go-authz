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

import (
	"context"
	"log/slog"
)

// Policy is the built-in Evaluator. It holds an ordered set of rules, a default
// effect used when no rule decides, and a combining algorithm. The zero
// interior (no rules, Deny default, FirstApplicable) is a complete
// default-deny-all policy.
type Policy struct {
	rules   []Rule
	def     Effect
	combine CombiningAlgorithm
	logger  *slog.Logger
}

// Option configures a Policy at construction.
type Option func(*Policy)

// WithDefaultEffect sets the effect used when no rule applies. The default is
// Deny.
func WithDefaultEffect(e Effect) Option { return func(p *Policy) { p.def = e } }

// WithCombiner sets the combining algorithm. The default is FirstApplicable.
func WithCombiner(c CombiningAlgorithm) Option {
	return func(p *Policy) {
		if c != nil {
			p.combine = c
		}
	}
}

// WithRules appends rules to the policy. It may be combined with Add.
func WithRules(rules ...Rule) Option {
	return func(p *Policy) { p.rules = append(p.rules, rules...) }
}

// WithLogger enables decision logging via the standard library log/slog. Each
// decision is emitted at Debug level. A nil logger (the default) is silent.
func WithLogger(l *slog.Logger) Option { return func(p *Policy) { p.logger = l } }

// NewPolicy builds a Policy. With no options it denies everything.
func NewPolicy(opts ...Option) *Policy {
	p := &Policy{def: Deny, combine: FirstApplicable}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Add appends rules and returns the policy for chaining.
func (p *Policy) Add(rules ...Rule) *Policy {
	p.rules = append(p.rules, rules...)
	return p
}

// Decide evaluates req against the policy and returns the Decision.
func (p *Policy) Decide(ctx context.Context, req Request) Decision {
	d := p.combine(ctx, req, p.rules, p.def)
	if p.logger != nil {
		p.logger.DebugContext(ctx, "authz decision",
			slog.String("subject", req.Subject),
			slog.String("resource", req.Resource),
			slog.String("action", req.Action),
			slog.String("effect", d.Effect.String()),
			slog.String("reason", d.Reason),
			slog.String("rule_id", d.RuleID),
		)
	}
	return d
}

var _ Evaluator = (*Policy)(nil)
