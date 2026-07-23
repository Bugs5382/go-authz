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

// Reason codes describe, in machine-readable form, why a Decision has its
// Effect. They are intended for downstream auth-decision logging.
const (
	// ReasonRuleMatched means an applicable rule produced the effect; the
	// Decision's RuleID names that rule.
	ReasonRuleMatched = "rule_matched"
	// ReasonNoMatch means no rule was applicable and the policy's default
	// effect was used; RuleID is empty.
	ReasonNoMatch = "no_matching_rule"
)

// Decision is the result of evaluating a Request.
//
// Reason is a stable, machine-readable code (see the Reason constants) and
// RuleID names the rule responsible, or is empty when the default effect
// applied. Together they give downstream logging a complete, greppable record.
type Decision struct {
	Effect Effect
	Reason string
	RuleID string
}

// Allowed reports whether the decision permits the request.
func (d Decision) Allowed() bool { return d.Effect == Allow }
