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
	"fmt"

	"github.com/Bugs5382/go-authz/ordered"
)

func ExampleDecide() {
	rs := ordered.RuleSet{
		Categories: map[string]ordered.Category{
			"policies": {
				Owners: []string{"user:erin"},
				Entries: []ordered.Entry{
					{Subject: "user:ann", Action: "approve", Effect: ordered.Deny},
					{Subject: "group:finance", Action: "approve", Effect: ordered.Allow},
					{Subject: ordered.Everyone, Action: "read", Effect: ordered.Allow},
				},
			},
		},
		Parents: map[string]string{"security-policy": "policies"},
	}
	dave := ordered.Person{ID: "dave", Groups: []string{"finance"}}
	ann := ordered.Person{ID: "ann", Groups: []string{"finance"}}

	// Rows are read from the top, per action: Ann's own deny comes first.
	fmt.Println(ordered.Decide(rs, dave, "security-policy", "approve").Allowed)
	fmt.Println(ordered.Decide(rs, ann, "security-policy", "approve").Allowed)

	// Everyone reads, and inherited rows apply to the child category.
	d := ordered.Decide(rs, ann, "security-policy", "read")
	fmt.Println(d.Allowed, d.Reason, d.DecidedBy.Category)

	// Owners always have read, author, approve and manage.
	fmt.Println(ordered.Decide(rs, ordered.Person{ID: "erin"}, "security-policy", "manage").Reason)
	// Output:
	// true
	// false
	// true entry policies
	// owner
}

func ExampleModel_superusers() {
	m := ordered.DefaultModel()
	m.Superusers = &ordered.Superusers{
		Subjects: []string{"role:root"},
		Actions:  []string{"read", "author", "approve", "manage"},
	}
	rs := ordered.RuleSet{Categories: map[string]ordered.Category{
		"c": {Entries: []ordered.Entry{{Subject: ordered.Everyone, Action: "read", Effect: ordered.Deny}}},
	}}
	root := ordered.Person{ID: "someone", Roles: []string{"root"}}

	// The seat follows the role, a deny is ignored, and it is reported.
	d := m.Decide(rs, root, "c", "read")
	fmt.Println(d.Allowed, d.Reason, d.ConfiguredBlock.Subject)
	// Output:
	// true superuser everyone:*
}

func ExamplePool() {
	rs := ordered.RuleSet{Categories: map[string]ordered.Category{
		"c": {
			Owners:  []string{"user:erin"},
			Entries: []ordered.Entry{{Subject: "group:finance", Action: "approve", Effect: ordered.Allow}},
		},
	}}
	people := []ordered.Person{
		{ID: "dave", Groups: []string{"finance"}},
		{ID: "erin"},
		{ID: "bob"},
	}
	for _, e := range ordered.Pool(rs, people, "c", "approve") {
		fmt.Println(e.Person, e.Reason)
	}
	// Output:
	// erin owner
	// dave entry
}
