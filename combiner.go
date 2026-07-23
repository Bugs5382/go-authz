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

// CombiningAlgorithm folds the applicable rules of a policy into a single
// Decision. def is the policy's default effect, used when no rule decides.
// Applications may supply their own algorithm to WithCombiner.
type CombiningAlgorithm func(ctx context.Context, req Request, rules []Rule, def Effect) Decision

func defaultDecision(def Effect) Decision {
	return Decision{Effect: def, Reason: ReasonNoMatch}
}

func matchedDecision(r Rule, e Effect) Decision {
	return Decision{Effect: e, Reason: ReasonRuleMatched, RuleID: r.ID()}
}

// FirstApplicable returns the verdict of the first applicable rule, in order,
// and falls back to the default effect when none applies. It is the default
// combining algorithm.
func FirstApplicable(ctx context.Context, req Request, rules []Rule, def Effect) Decision {
	for _, r := range rules {
		if e, ok := r.Eval(ctx, req); ok {
			return matchedDecision(r, e)
		}
	}
	return defaultDecision(def)
}

// DenyOverrides returns Deny if any applicable rule denies, otherwise Allow if
// any applicable rule allows, otherwise the default effect. Use it when a
// single denial must veto every grant.
func DenyOverrides(ctx context.Context, req Request, rules []Rule, def Effect) Decision {
	var allow *Rule
	for i := range rules {
		e, ok := rules[i].Eval(ctx, req)
		if !ok {
			continue
		}
		if e == Deny {
			return matchedDecision(rules[i], Deny)
		}
		if allow == nil {
			allow = &rules[i]
		}
	}
	if allow != nil {
		return matchedDecision(*allow, Allow)
	}
	return defaultDecision(def)
}

// AllowOverrides returns Allow if any applicable rule allows, otherwise Deny if
// any applicable rule denies, otherwise the default effect.
func AllowOverrides(ctx context.Context, req Request, rules []Rule, def Effect) Decision {
	var deny *Rule
	for i := range rules {
		e, ok := rules[i].Eval(ctx, req)
		if !ok {
			continue
		}
		if e == Allow {
			return matchedDecision(rules[i], Allow)
		}
		if deny == nil {
			deny = &rules[i]
		}
	}
	if deny != nil {
		return matchedDecision(*deny, Deny)
	}
	return defaultDecision(def)
}
