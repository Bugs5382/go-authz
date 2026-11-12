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

// PoolEntry is one person in a pool and why they are in it.
type PoolEntry struct {
	// Person is the Person.ID.
	Person string `json:"person"`
	// Reason is ReasonOwner, ReasonSuperuser or ReasonEntry.
	Reason string `json:"reason"`
	// Category is where the person owns, or where the deciding row is.
	Category string `json:"category"`
	// Row is the 0-based position of the deciding row in its category, when a
	// row decided directly.
	Row *int `json:"row,omitempty"`
	// Everyone is true when the deciding row is the Everyone row.
	Everyone bool `json:"everyone,omitempty"`
}

// Pool lists the people for whom the action answers allowed in the category:
// owners first, then the superuser seat, then the people a row allows, each in
// the order of people. It is the approver pool for an approve action and the
// acknowledge list for an ack action. A pure listing; the host decides what to
// do with it. The result is never nil.
func (m Model) Pool(rs RuleSet, people []Person, category, action string) []PoolEntry {
	var owners, superusers, rows []PoolEntry
	for _, p := range people {
		d := m.Decide(rs, p, category, action)
		if !d.Allowed {
			continue
		}
		entry := PoolEntry{Person: p.ID, Reason: d.Reason, Category: d.at}
		switch d.Reason {
		case ReasonOwner:
			owners = append(owners, entry)
		case ReasonSuperuser:
			superusers = append(superusers, entry)
		default:
			entry.Category = d.DecidedBy.Category
			if d.row > 0 {
				r := d.row - 1
				entry.Row = &r
			}
			entry.Everyone = d.DecidedBy.Subject == Everyone
			rows = append(rows, entry)
		}
	}
	out := make([]PoolEntry, 0, len(owners)+len(superusers)+len(rows))
	out = append(out, owners...)
	out = append(out, superusers...)
	return append(out, rows...)
}
