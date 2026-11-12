package ordered

import "slices"

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

func kindOf(subject string) string {
	for i := 0; i < len(subject); i++ {
		if subject[i] == ':' {
			return subject[:i]
		}
	}
	return ""
}

// subjectsOf returns the set of subjects the person matches.
func (m Model) subjectsOf(p Person) map[string]bool {
	set := map[string]bool{}
	if p.ID != "" {
		set["user:"+p.ID] = true
	}
	for _, g := range p.Groups {
		set["group:"+g] = true
	}
	for _, r := range p.Roles {
		set["role:"+r] = true
	}
	for _, s := range p.Subjects {
		set[s] = true
	}
	implicit := m.ImplicitSubjects
	if implicit == nil {
		implicit = []string{Everyone}
	}
	for _, s := range implicit {
		set[s] = true
	}
	return set
}

// row is the cells of one subject in a category.
type row struct {
	subject string
	cells   []Entry
}

// rowsOf groups entries into rows by subject, in order of first appearance.
func rowsOf(entries []Entry) []row {
	var rows []row
	index := map[string]int{}
	for _, e := range entries {
		i, ok := index[e.Subject]
		if !ok {
			i = len(rows)
			index[e.Subject] = i
			rows = append(rows, row{subject: e.Subject})
		}
		rows[i].cells = append(rows[i].cells, e)
	}
	return rows
}

// closure is every action an entry on id covers: itself plus all it implies,
// transitively. It is safe against cycles.
func closure(id string, byID map[string]Action) map[string]bool {
	seen := map[string]bool{id: true}
	queue := []string{id}
	for len(queue) > 0 {
		next := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, implied := range byID[next].Implies {
			if !seen[implied] {
				seen[implied] = true
				queue = append(queue, implied)
			}
		}
	}
	return seen
}

// evaluation is one Decide call.
type evaluation struct {
	m        Model
	rs       RuleSet
	byID     map[string]Action
	subjects map[string]bool
	category string
	chain    []string
}

func (e *evaluation) ownerHas(id string) bool {
	if e.m.OwnerActions != nil {
		return slices.Contains(e.m.OwnerActions, id)
	}
	a := e.byID[id]
	if a.OwnerHas != nil {
		return *a.OwnerHas
	}
	return a.Kind != KindObligation
}

// core answers one action with no implication and no gating. rulesOnly leaves
// the superuser seat out, to find the entry that would have denied it.
func (e *evaluation) core(act string, rulesOnly bool) Decision {
	if su := e.m.Superusers; !rulesOnly && su != nil && slices.Contains(su.Actions, act) {
		for _, s := range su.Subjects {
			if e.subjects[s] {
				return Decision{Allowed: true, Reason: ReasonSuperuser, at: e.category}
			}
		}
	}
	if e.ownerHas(act) {
		kinds := e.m.OwnerKinds
		if kinds == nil {
			kinds = []string{"user"}
		}
		for _, cat := range e.chain {
			for _, o := range e.rs.Categories[cat].Owners {
				if slices.Contains(kinds, kindOf(o)) && e.subjects[o] {
					return Decision{Allowed: true, Reason: ReasonOwner, at: cat}
				}
			}
		}
	}
	for _, cat := range e.chain {
		for i, r := range rowsOf(e.rs.Categories[cat].Entries) {
			if !e.subjects[r.subject] {
				continue
			}
			for _, c := range r.cells {
				if c.Action == act {
					return Decision{
						Allowed:   c.Effect == Allow,
						Reason:    ReasonEntry,
						DecidedBy: &Entry{Category: cat, Subject: c.Subject, Action: c.Action, Effect: c.Effect},
						row:       i + 1,
					}
				}
			}
		}
	}
	return Decision{Reason: ReasonDefaultDeny}
}

// confer lets an allowed higher action give the action it implies, even over
// an explicit deny of the lower one. It only goes down, and only from what a
// row or an owner allows.
func (e *evaluation) confer(act string, rulesOnly bool) (Decision, bool) {
	for _, higher := range e.m.Actions {
		if higher.ID == act || !closure(higher.ID, e.byID)[act] {
			continue
		}
		if d := e.core(higher.ID, rulesOnly); d.Allowed {
			return d, true
		}
	}
	return Decision{}, false
}

func (e *evaluation) answer(act string, rulesOnly bool) Decision {
	d := e.core(act, rulesOnly)
	if d.Allowed {
		return d
	}
	if c, ok := e.confer(act, rulesOnly); ok {
		// The row of a conferred answer is the row of the asked action's own
		// deny, when that deny sits in the same category as the higher entry;
		// otherwise the answer has no row of its own.
		c.row = 0
		if d.DecidedBy != nil && c.DecidedBy != nil && d.DecidedBy.Category == c.DecidedBy.Category {
			c.row = d.row
		}
		return c
	}
	return d
}

// Decide answers whether the person may do the action in the category. It is a
// pure evaluation helper; the host enforces.
//
// An unknown action is a default deny. The superuser seat is checked first,
// then owners, then the rows (see the package documentation).
func (m Model) Decide(rs RuleSet, p Person, category, action string) Decision {
	byID := make(map[string]Action, len(m.Actions))
	for _, a := range m.Actions {
		byID[a.ID] = a
	}
	if _, ok := byID[action]; !ok {
		return Decision{Reason: ReasonDefaultDeny}
	}
	e := &evaluation{m: m, rs: rs, byID: byID, subjects: m.subjectsOf(p), category: category}
	for at, ok := category, true; ok && !slices.Contains(e.chain, at); at, ok = rs.Parents[at] {
		e.chain = append(e.chain, at)
	}

	d := e.answer(action, false)
	if d.Reason == ReasonSuperuser {
		if rules := e.answer(action, true); !rules.Allowed && rules.DecidedBy != nil {
			blocked := *rules.DecidedBy
			d.ConfiguredBlock = &blocked
		}
	}
	if d.Allowed && d.Reason == ReasonEntry {
		for _, required := range byID[action].Requires {
			if !e.answer(required, false).Allowed {
				return Decision{Reason: ReasonRequires, GatedBy: required}
			}
		}
	}
	return d
}
