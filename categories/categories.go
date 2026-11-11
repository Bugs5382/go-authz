// Package categories resolves access for a person against a tree of
// categories. It implements the approved category model on top of the
// authz engine.
//
// Subjects are plain strings such as "user:alice", "group:finance" and
// "role:approver". A resource is a category with an optional parent chain. An
// Action may imply other actions, and an Entry on action A matches a question
// about any action A includes.
//
// A question is answered by walking from the category up its parent chain.
// At the nearest category that has any entry matching one of the person's
// subjects and the asked action, a Deny beats an Allow, otherwise Allow. A
// category with StopInheriting ends the walk after its own entries. After the
// root the category "*" is the last stop, skipped when the walk already
// stopped. With no match the answer is the default deny.
//
// Inside one category the work is done by an authz.Policy with the
// authz.DenyOverrides combiner, so the first deciding entry in entry order is
// the one reported.
package categories

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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Bugs5382/go-authz"
)

// Last is the category id that is the final stop of every walk.
const Last = "*"

// Reasons reported in a Result.
const (
	// ReasonEntry means an entry decided the answer.
	ReasonEntry = "entry"
	// ReasonDefaultDeny means no entry matched and access is denied.
	ReasonDefaultDeny = "default-deny"
)

// subjectsAttr is the Request attribute that carries the person's subjects.
const subjectsAttr = "subjects"

// Action defines one action and the actions it implies. Implications are
// transitive; a cycle is harmless.
type Action struct {
	ID      string   `json:"id"`
	Implies []string `json:"implies"`
}

// Entry is one rule of a category: Subject is allowed or denied Action.
type Entry struct {
	Subject string
	Action  string
	Effect  authz.Effect
}

type wireEntry struct {
	Subject string `json:"subject"`
	Action  string `json:"action"`
	Effect  string `json:"effect"`
}

// UnmarshalJSON decodes {"subject","action","effect":"allow|deny"}. Any other
// effect is an error, so a typo can never become a silent deny or allow.
func (e *Entry) UnmarshalJSON(b []byte) error {
	var w wireEntry
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	switch w.Effect {
	case "allow":
		e.Effect = authz.Allow
	case "deny":
		e.Effect = authz.Deny
	default:
		return fmt.Errorf("categories: unknown effect %q", w.Effect)
	}
	e.Subject, e.Action = w.Subject, w.Action
	return nil
}

// Category holds the entries of one category.
type Category struct {
	StopInheriting bool    `json:"stopInheriting"`
	Entries        []Entry `json:"entries"`
}

// RuleSet is the wire format: the categories by id and the parent of each
// child category. A category missing from Parents is a root.
type RuleSet struct {
	Categories map[string]Category `json:"categories"`
	Parents    map[string]string   `json:"parents"`
}

// Source names the category and entry that decided a Result.
type Source struct {
	Category string
	Entry    Entry
}

// Result is the answer to a question. DecidedBy is nil for a default deny.
type Result struct {
	Allowed   bool
	Reason    string
	DecidedBy *Source
}

type compiled struct {
	stop    bool
	policy  *authz.Policy
	entries map[string]Entry
}

// Resolver answers questions against one RuleSet. It is immutable after New and
// safe for concurrent use.
type Resolver struct {
	parents map[string]string
	cats    map[string]compiled
	closure map[string]map[string]bool
}

// New compiles rs and the action definitions into a Resolver.
func New(rs RuleSet, actions []Action) *Resolver {
	implies := make(map[string][]string, len(actions))
	for _, a := range actions {
		implies[a.ID] = a.Implies
	}
	r := &Resolver{
		parents: rs.Parents,
		cats:    make(map[string]compiled, len(rs.Categories)),
		closure: make(map[string]map[string]bool, len(actions)),
	}
	for _, a := range actions {
		seen := map[string]bool{}
		var visit func(string)
		visit = func(id string) {
			if seen[id] {
				return
			}
			seen[id] = true
			for _, next := range implies[id] {
				visit(next)
			}
		}
		visit(a.ID)
		r.closure[a.ID] = seen
	}
	for id, c := range rs.Categories {
		r.cats[id] = r.compile(c)
	}
	return r
}

func (r *Resolver) compile(c Category) compiled {
	out := compiled{stop: c.StopInheriting, entries: make(map[string]Entry, len(c.Entries))}
	rules := make([]authz.Rule, 0, len(c.Entries))
	for i, e := range c.Entries {
		id := strconv.Itoa(i)
		out.entries[id] = e
		rules = append(rules, authz.NewRule(id, e.Effect, func(_ context.Context, req authz.Request) bool {
			subjects, _ := req.Attr(subjectsAttr)
			_, known := r.closure[req.Action]
			return known && subjects.(map[string]bool)[e.Subject] && r.closure[e.Action][req.Action]
		}))
	}
	out.policy = authz.NewPolicy(authz.WithRules(rules...), authz.WithCombiner(authz.DenyOverrides))
	return out
}

// Resolve answers whether a person with the given subjects may perform action
// on category. An action that no definition lists is a default deny.
func (r *Resolver) Resolve(ctx context.Context, subjects []string, category, action string) Result {
	set := make(map[string]bool, len(subjects))
	for _, s := range subjects {
		set[s] = true
	}
	visited := map[string]bool{}
	for id, ok := category, true; ok && !visited[id]; id, ok = r.parents[id] {
		visited[id] = true
		if res, done := r.decide(ctx, set, id, action); done {
			return res
		}
		if r.cats[id].stop {
			return Result{Reason: ReasonDefaultDeny}
		}
	}
	if !visited[Last] {
		if res, done := r.decide(ctx, set, Last, action); done {
			return res
		}
	}
	return Result{Reason: ReasonDefaultDeny}
}

func (r *Resolver) decide(ctx context.Context, subjects map[string]bool, category, action string) (Result, bool) {
	c, ok := r.cats[category]
	if !ok {
		return Result{}, false
	}
	d := c.policy.Decide(ctx, authz.Request{
		Resource:   category,
		Action:     action,
		Attributes: map[string]any{subjectsAttr: subjects},
	})
	if d.Reason != authz.ReasonRuleMatched {
		return Result{}, false
	}
	return Result{
		Allowed:   d.Allowed(),
		Reason:    ReasonEntry,
		DecidedBy: &Source{Category: category, Entry: c.entries[d.RuleID]},
	}, true
}
