package ordered_test

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
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Bugs5382/go-authz/ordered"
)

// vectorFile is the shared vectors file. It is decoded strictly: a field the
// runner does not know is a failure to report, not to ignore.
type vectorFile struct {
	Version int    `json:"version"`
	Model   string `json:"model"`
	Options struct {
		Superusers *ordered.Superusers `json:"superusers"`
	} `json:"options"`
	Actions []ordered.Action `json:"actions"`
	Cases   []vectorCase     `json:"cases"`
	Pools   []vectorPool     `json:"pools"`
}

type vectorCase struct {
	Name     string          `json:"name"`
	RuleSet  ordered.RuleSet `json:"ruleSet"`
	Person   ordered.Person  `json:"person"`
	Category string          `json:"category"`
	Action   string          `json:"action"`
	Expect   struct {
		Allowed         bool           `json:"allowed"`
		Reason          string         `json:"reason"`
		DecidedBy       *ordered.Entry `json:"decidedBy"`
		GatedBy         string         `json:"gatedBy"`
		ConfiguredBlock *ordered.Entry `json:"configuredBlock"`
	} `json:"expect"`
}

type vectorPool struct {
	Name     string              `json:"name"`
	RuleSet  ordered.RuleSet     `json:"ruleSet"`
	People   []ordered.Person    `json:"people"`
	Category string              `json:"category"`
	Action   string              `json:"action"`
	Expect   []ordered.PoolEntry `json:"expect"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../testdata/ordered.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v vectorFile
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	if v.Model != "ordered" {
		t.Skipf("vectors file is for model %q, not implemented here", v.Model)
	}
	if len(v.Cases) < 74 {
		t.Fatalf("expected at least 74 cases, got %d", len(v.Cases))
	}
	m := ordered.Model{Actions: v.Actions, Superusers: v.Options.Superusers}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			d := m.Decide(c.RuleSet, c.Person, c.Category, c.Action)
			if d.Allowed != c.Expect.Allowed {
				t.Errorf("allowed = %v, want %v", d.Allowed, c.Expect.Allowed)
			}
			if d.Reason != c.Expect.Reason {
				t.Errorf("reason = %q, want %q", d.Reason, c.Expect.Reason)
			}
			if !reflect.DeepEqual(d.DecidedBy, c.Expect.DecidedBy) {
				t.Errorf("decidedBy = %+v, want %+v", d.DecidedBy, c.Expect.DecidedBy)
			}
			if d.GatedBy != c.Expect.GatedBy {
				t.Errorf("gatedBy = %q, want %q", d.GatedBy, c.Expect.GatedBy)
			}
			if !reflect.DeepEqual(d.ConfiguredBlock, c.Expect.ConfiguredBlock) {
				t.Errorf("configuredBlock = %+v, want %+v", d.ConfiguredBlock, c.Expect.ConfiguredBlock)
			}
		})
	}
}

func TestVectorPools(t *testing.T) {
	v := loadVectors(t)
	if v.Model != "ordered" {
		t.Skipf("vectors file is for model %q, not implemented here", v.Model)
	}
	if len(v.Pools) == 0 {
		t.Fatal("no pools in the vectors")
	}
	m := ordered.Model{Actions: v.Actions, Superusers: v.Options.Superusers}
	for _, p := range v.Pools {
		t.Run(p.Name, func(t *testing.T) {
			got := m.Pool(p.RuleSet, p.People, p.Category, p.Action)
			if !reflect.DeepEqual(got, p.Expect) {
				t.Errorf("pool = %+v, want %+v", got, p.Expect)
			}
		})
	}
}
