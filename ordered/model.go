// Package ordered implements a firewall-style access model: rows of rules read
// from the top, one decision per action, inherited rows after a category's own.
//
// A rule set holds categories. Each category has entries (a subject, an action
// and an effect) and may list owners. Entries that share a subject form a row
// and a row has at most one cell per action. For one action the rows of the
// category are read from the top, then its parent's, and so on; the first row
// that matches the person and has a cell for the asked action decides. An empty
// cell is skipped: a cell answers only its own action.
//
// Owners always have the actions their category lists as theirs, whatever any
// row says. An allowed higher action gives the lower actions it implies, even
// over an explicit deny of the lower one. An action that requires another is
// denied when the required one is. A host-configured superuser seat (one seat,
// for example role:root) is exempt only for the access actions it lists, such
// as read, author and manage, and a deny that would have applied is reported as
// Decision.ConfiguredBlock. Approve and ack, and any obligation, are never
// exempt, even when listed: they follow the rows for the seat too. The default
// is deny.
//
// The behaviour is pinned by the shared vectors file in testdata/ordered.json.
// The package is independent of the root go-authz package.
package ordered

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

// Everyone is the built-in subject every person has.
const Everyone = "everyone:*"

// KindObligation marks an action that is owed rather than held (approve,
// acknowledge). Owners have an action unless it is an obligation, or unless
// the action sets OwnerHas.
const KindObligation = "obligation"

// Effect is the outcome of a rule.
type Effect string

// The two effects of a cell.
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// The reasons a Decision can carry.
const (
	// ReasonEntry means a row decided (directly or through a higher action).
	ReasonEntry = "entry"
	// ReasonDefaultDeny means no row decided, or the action is unknown.
	ReasonDefaultDeny = "default-deny"
	// ReasonOwner means an owner of the category or an ancestor.
	ReasonOwner = "owner"
	// ReasonSuperuser means the configured superuser seat.
	ReasonSuperuser = "superuser"
	// ReasonRequires means a required action was denied; see Decision.GatedBy.
	ReasonRequires = "requires"
)

// Entry is one cell: the subject, the action and the effect. Category is set
// on the entries a Decision reports and names where the entry lives; it is
// ignored inside a RuleSet.
type Entry struct {
	Category string `json:"category,omitempty"`
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Effect   Effect `json:"effect"`
}

// Category holds the rules of one category.
type Category struct {
	// Entries are the cells, in order. Entries of one subject form a row, and
	// rows are ordered by the first appearance of their subject.
	Entries []Entry `json:"entries"`
	// Owners are subjects (of a kind Model.OwnerKinds allows) that own the
	// category and every category below it.
	Owners []string `json:"owners,omitempty"`
	// StopInheriting is ignored by this model: inherited rows always apply.
	StopInheriting bool `json:"stopInheriting,omitempty"`
}

// RuleSet is the categories and their parent chain.
type RuleSet struct {
	Categories map[string]Category `json:"categories"`
	// Parents maps a child category to its parent. A category that is not a key
	// is a root. A cycle ends the walk.
	Parents map[string]string `json:"parents"`
}

// Person is whom a decision is about. The subjects the model matches are
// "user:<ID>" (when ID is not empty), "group:<g>" for each group, "role:<r>" for
// each role, then Subjects as given, then the implicit subjects.
type Person struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	// Subjects are extra matchers added as they are, for example "can:ack".
	Subjects []string `json:"subjects,omitempty"`
}

// Action defines one action of the model.
type Action struct {
	ID string `json:"id"`
	// Implies lists the actions an allow of this one gives (transitively).
	Implies []string `json:"implies,omitempty"`
	// Kind is KindObligation or empty.
	Kind string `json:"kind,omitempty"`
	// Requires lists actions that must also be answered allowed.
	Requires []string `json:"requires,omitempty"`
	// OwnerHas says whether owners have the action; nil means every action
	// that is not an obligation.
	OwnerHas *bool `json:"ownerHas,omitempty"`
}

// Superusers is the host-configured seat that is exempt from the rows for the
// access actions it lists. Obligations (Kind obligation) and the actions named
// approve and ack are never exempt, even when listed.
type Superusers struct {
	// Subjects name the seat, for example "role:root". The seat follows the
	// subject, never a name.
	Subjects []string `json:"subjects"`
	// Actions are the access actions the seat always has, for example read,
	// author and manage. An action not listed, and any obligation, follows the
	// rows like anyone else's.
	Actions []string `json:"actions"`
}

// Model is the configuration of the engine. The zero value knows no action, so
// it denies everything; see DefaultModel.
type Model struct {
	// Actions are the known actions. An unknown action is a default deny.
	Actions []Action
	// OwnerKinds are the subject kinds that may own a category. Nil means
	// ["user"]; an empty non-nil list switches owners off.
	OwnerKinds []string
	// ImplicitSubjects are subjects everyone has. Nil means [Everyone].
	ImplicitSubjects []string
	// OwnerActions lists the actions owners always have. Nil derives them from
	// each action's OwnerHas and Kind.
	OwnerActions []string
	// Superusers is the exempt seat, or nil for none.
	Superusers *Superusers
}

// Decision is the answer to one question.
type Decision struct {
	Allowed bool
	// Reason is one of the Reason constants.
	Reason string
	// DecidedBy is the entry that decided, or nil for a default deny, an owner,
	// the superuser seat and a failed requirement. After an allowed higher
	// action gave the answer it is the higher action's entry.
	DecidedBy *Entry
	// ConfiguredBlock is set with ReasonSuperuser: the entry that would have
	// denied the seat if it were subject to the rows.
	ConfiguredBlock *Entry
	// GatedBy names the required action that was not allowed (ReasonRequires).
	GatedBy string

	// at is where the owner or the superuser seat applied; row is the 1-based
	// position of the deciding row when a row decided directly (0 for none).
	at  string
	row int
}

// DefaultActions are the five actions of the shared vectors: read; author;
// approve (an obligation owners have); manage; and ack, an obligation that
// requires read.
func DefaultActions() []Action {
	yes := true
	return []Action{
		{ID: "read"},
		{ID: "author", Implies: []string{"read"}},
		{ID: "approve", Implies: []string{"read"}, Kind: KindObligation, OwnerHas: &yes},
		{ID: "manage", Implies: []string{"author", "read"}},
		{ID: "ack", Kind: KindObligation, Requires: []string{"read"}},
	}
}

// DefaultModel returns the model of the shared vectors: DefaultActions, user
// owners, the Everyone subject and no superuser seat.
func DefaultModel() Model { return Model{Actions: DefaultActions()} }

// Decide answers whether the person may do the action in the category, using
// DefaultModel. Use a Model to change the actions or add a superuser seat.
func Decide(rs RuleSet, p Person, category, action string) Decision {
	return DefaultModel().Decide(rs, p, category, action)
}

// Pool lists who the action answers allowed for, using DefaultModel.
func Pool(rs RuleSet, people []Person, category, action string) []PoolEntry {
	return DefaultModel().Pool(rs, people, category, action)
}
