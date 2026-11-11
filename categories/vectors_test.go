package categories_test

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
	"os"
	"testing"

	"github.com/Bugs5382/go-authz"
	"github.com/Bugs5382/go-authz/categories"
)

type vectorFile struct {
	Version int                 `json:"version"`
	Actions []categories.Action `json:"actions"`
	Cases   []vectorCase        `json:"cases"`
}

type vectorCase struct {
	Name     string             `json:"name"`
	RuleSet  categories.RuleSet `json:"ruleSet"`
	Person   vectorPerson       `json:"person"`
	Category string             `json:"category"`
	Action   string             `json:"action"`
	Expect   vectorExpect       `json:"expect"`
}

type vectorPerson struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"`
	Roles  []string `json:"roles"`
}

type vectorExpect struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	DecidedBy *struct {
		Category string `json:"category"`
		Subject  string `json:"subject"`
		Action   string `json:"action"`
		Effect   string `json:"effect"`
	} `json:"decidedBy"`
}

// subjects maps a person to the subject strings the model matches on.
func (p vectorPerson) subjects() []string {
	out := []string{"user:" + p.ID}
	for _, g := range p.Groups {
		out = append(out, "group:"+g)
	}
	for _, r := range p.Roles {
		out = append(out, "role:"+r)
	}
	return out
}

func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/decide.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if vf.Version != 1 || len(vf.Cases) == 0 {
		t.Fatalf("unexpected vector file: version %d, %d cases", vf.Version, len(vf.Cases))
	}
	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r := categories.New(c.RuleSet, vf.Actions)
			got := r.Resolve(context.Background(), c.Person.subjects(), c.Category, c.Action)
			if got.Allowed != c.Expect.Allowed {
				t.Errorf("allowed = %v, want %v", got.Allowed, c.Expect.Allowed)
			}
			if got.Reason != c.Expect.Reason {
				t.Errorf("reason = %q, want %q", got.Reason, c.Expect.Reason)
			}
			want := c.Expect.DecidedBy
			switch {
			case want == nil && got.DecidedBy != nil:
				t.Errorf("decidedBy = %+v, want none", got.DecidedBy)
			case want != nil && got.DecidedBy == nil:
				t.Errorf("decidedBy = none, want %+v", want)
			case want != nil:
				if got.DecidedBy.Category != want.Category ||
					got.DecidedBy.Entry.Subject != want.Subject ||
					got.DecidedBy.Entry.Action != want.Action ||
					got.DecidedBy.Entry.Effect.String() != want.Effect {
					t.Errorf("decidedBy = %+v, want %+v", got.DecidedBy, want)
				}
			}
		})
	}
}

func TestEntryUnmarshal(t *testing.T) {
	var e categories.Entry
	if err := json.Unmarshal([]byte(`{"subject":"user:a","action":"read","effect":"allow"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Subject != "user:a" || e.Action != "read" || e.Effect != authz.Allow {
		t.Errorf("decoded %+v", e)
	}
	if err := json.Unmarshal([]byte(`{"subject":"user:a","action":"read","effect":"maybe"}`), &e); err == nil {
		t.Error("an unknown effect must be an error")
	}
	if err := json.Unmarshal([]byte(`{"subject":1}`), &e); err == nil {
		t.Error("a malformed entry must be an error")
	}
}

// An action that only appears in another action's implies list is not a
// defined action, so asking about it is a default deny.
func TestImpliedButUnlistedActionIsDenied(t *testing.T) {
	rs := categories.RuleSet{Categories: map[string]categories.Category{
		"c": {Entries: []categories.Entry{{Subject: "user:a", Action: "manage", Effect: authz.Allow}}},
	}}
	r := categories.New(rs, []categories.Action{{ID: "manage", Implies: []string{"ghost"}}})
	if got := r.Resolve(context.Background(), []string{"user:a"}, "c", "ghost"); got.Allowed {
		t.Errorf("ghost allowed: %+v", got)
	}
	if got := r.Resolve(context.Background(), []string{"user:a"}, "c", "manage"); !got.Allowed {
		t.Errorf("manage denied: %+v", got)
	}
}
