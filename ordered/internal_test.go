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

import "testing"

func TestConferredRowFollowsOwnDenyInSameCategory(t *testing.T) {
	rs := RuleSet{Categories: map[string]Category{
		"c": {Entries: []Entry{
			{Subject: "user:a", Action: "read", Effect: Deny},
			{Subject: "user:a", Action: "author", Effect: Allow},
		}},
	}}
	pool := Pool(rs, []Person{{ID: "a"}}, "c", "read")
	if len(pool) != 1 || pool[0].Row == nil || *pool[0].Row != 0 {
		t.Fatalf("pool = %+v, want row 0", pool)
	}
	// Higher entry in a different category than the own deny: no row.
	rs = RuleSet{
		Categories: map[string]Category{
			"c": {Entries: []Entry{{Subject: "user:a", Action: "read", Effect: Deny}}},
			"p": {Entries: []Entry{{Subject: "user:a", Action: "author", Effect: Allow}}},
		},
		Parents: map[string]string{"c": "p"},
	}
	pool = Pool(rs, []Person{{ID: "a"}}, "c", "read")
	if len(pool) != 1 || pool[0].Row != nil {
		t.Fatalf("pool = %+v, want no row", pool)
	}
}

func TestOwnerOptions(t *testing.T) {
	rs := RuleSet{Categories: map[string]Category{
		"c": {Owners: []string{"bare", "user:o", "group:g"}},
	}}
	m := DefaultModel()
	if m.Decide(rs, Person{ID: "bare"}, "c", "read").Allowed {
		t.Error("an owner without a kind must not match")
	}
	if !m.Decide(rs, Person{ID: "o"}, "c", "manage").Allowed {
		t.Error("a user owner has manage")
	}
	if m.Decide(rs, Person{Groups: []string{"g"}}, "c", "read").Allowed {
		t.Error("a group is not an owner kind by default")
	}
	m.OwnerKinds = []string{"user", "group"}
	if !m.Decide(rs, Person{Groups: []string{"g"}}, "c", "read").Allowed {
		t.Error("a group owns once its kind is allowed")
	}
	m.OwnerKinds = []string{}
	if m.Decide(rs, Person{ID: "o"}, "c", "read").Allowed {
		t.Error("an empty kind list switches owners off")
	}
	m.OwnerKinds = nil
	m.OwnerActions = []string{"read"}
	if !m.Decide(rs, Person{ID: "o"}, "c", "read").Allowed || m.Decide(rs, Person{ID: "o"}, "c", "manage").Allowed {
		t.Error("OwnerActions limits what owners have")
	}
}

func TestPackageLevelAndPoolSeats(t *testing.T) {
	rs := RuleSet{Categories: map[string]Category{
		"c": {Owners: []string{"user:o"}, Entries: []Entry{{Subject: Everyone, Action: "read", Effect: Allow}}},
	}}
	if d := Decide(rs, Person{ID: "x"}, "c", "read"); !d.Allowed || d.DecidedBy.Category != "c" {
		t.Errorf("decision = %+v", d)
	}
	m := DefaultModel()
	m.Superusers = &Superusers{Subjects: []string{"role:root"}, Actions: []string{"read"}}
	people := []Person{{ID: "x"}, {ID: "r", Roles: []string{"root"}}, {ID: "o"}}
	got := m.Pool(rs, people, "c", "read")
	if len(got) != 3 || got[0].Person != "o" || got[1].Person != "r" || got[1].Reason != ReasonSuperuser || !got[2].Everyone {
		t.Errorf("pool = %+v", got)
	}
	if p := Pool(rs, nil, "c", "read"); p == nil || len(p) != 0 {
		t.Errorf("empty pool = %#v, want non-nil empty", p)
	}
}

func TestZeroModelDeniesAndCyclesEnd(t *testing.T) {
	if (Model{}).Decide(RuleSet{}, Person{ID: "a"}, "c", "read").Allowed {
		t.Error("the zero model denies")
	}
	rs := RuleSet{
		Categories: map[string]Category{"a": {}, "b": {Entries: []Entry{{Subject: "user:x", Action: "read", Effect: Allow}}}},
		Parents:    map[string]string{"a": "b", "b": "a"},
	}
	if !Decide(rs, Person{ID: "x"}, "a", "read").Allowed {
		t.Error("a cycle ends the walk after visiting each category once")
	}
}

func TestSuperusersNeverExemptObligations(t *testing.T) {
	rs := RuleSet{Categories: map[string]Category{
		"c": {Entries: []Entry{
			{Subject: Everyone, Action: "approve", Effect: Deny},
			{Subject: Everyone, Action: "ack", Effect: Deny},
			{Subject: Everyone, Action: "read", Effect: Deny},
		}},
	}}
	root := Person{ID: "r", Roles: []string{"root"}}
	m := DefaultModel()
	m.Superusers = &Superusers{Subjects: []string{"role:root"}, Actions: []string{"read", "approve", "ack"}}

	// Read is listed and not an obligation: exempt, the deny is only reported.
	d := m.Decide(rs, root, "c", "read")
	if !d.Allowed || d.Reason != ReasonSuperuser || d.ConfiguredBlock == nil {
		t.Errorf("read = %+v, want a superuser allow with a configured block", d)
	}
	// Approve and ack are listed by the host but never exempt: the rows decide.
	for _, act := range []string{"approve", "ack"} {
		d := m.Decide(rs, root, "c", act)
		if d.Allowed || d.Reason == ReasonSuperuser || d.ConfiguredBlock != nil {
			t.Errorf("%s = %+v, want the rows to decide", act, d)
		}
	}
	// An action that is not named approve or ack but is an obligation is not exempt either.
	m.Actions = append(m.Actions, Action{ID: "attest", Kind: KindObligation})
	m.Superusers.Actions = append(m.Superusers.Actions, "attest")
	if d := m.Decide(rs, root, "c", "attest"); d.Allowed || d.Reason == ReasonSuperuser {
		t.Errorf("attest = %+v, want not exempt", d)
	}
	// A custom action named approve that is not an obligation is still never exempt.
	m.Actions = []Action{{ID: "approve"}, {ID: "read"}}
	if d := m.Decide(rs, root, "c", "approve"); d.Allowed || d.Reason == ReasonSuperuser {
		t.Errorf("custom approve = %+v, want not exempt", d)
	}
}
