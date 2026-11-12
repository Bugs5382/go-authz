package rbac_test

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
	"slices"
	"testing"

	"github.com/Bugs5382/go-authz/rbac"
)

// vectorFile is testdata/rbac.json, decoded strictly: a field the runner does
// not know is a failure to report, not to ignore. The file is plain data so a
// port of the catalog in another language can run the same cases.
type vectorFile struct {
	Version   int             `json:"version"`
	Catalog   json.RawMessage `json:"catalog"`
	Authorize []struct {
		Name       string          `json:"name"`
		Subject    rbac.Subject    `json:"subject"`
		Permission rbac.Permission `json:"permission"`
		Resource   *rbac.Resource  `json:"resource"`
		Expect     struct {
			Effect rbac.Effect `json:"effect"`
			Reason rbac.Reason `json:"reason"`
		} `json:"expect"`
	} `json:"authorize"`
	Capability []struct {
		Name       string          `json:"name"`
		Subject    rbac.Subject    `json:"subject"`
		Permission rbac.Permission `json:"permission"`
		Expect     bool            `json:"expect"`
	} `json:"capability"`
	PermissionsForRoles []struct {
		Name   string            `json:"name"`
		Roles  []rbac.Role       `json:"roles"`
		Expect []rbac.Permission `json:"expect"`
	} `json:"permissionsForRoles"`
}

func loadVectors(t *testing.T) (vectorFile, rbac.Catalog) {
	t.Helper()
	b, err := os.ReadFile("../testdata/rbac.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("vectors do not decode: %v", err)
	}
	if v.Version != 1 {
		t.Fatalf("vectors version %d, runner knows 1", v.Version)
	}
	c, err := rbac.Parse(v.Catalog)
	if err != nil {
		t.Fatalf("the vectors catalog must parse: %v", err)
	}
	return v, c
}

func TestVectors_Authorize(t *testing.T) {
	v, c := loadVectors(t)
	if len(v.Authorize) < 40 {
		t.Fatalf("only %d authorize cases; the file lost cases", len(v.Authorize))
	}
	for _, tc := range v.Authorize {
		t.Run(tc.Name, func(t *testing.T) {
			d := c.Authorize(tc.Subject, tc.Permission, tc.Resource)
			if d.Effect != tc.Expect.Effect || d.Reason != tc.Expect.Reason {
				t.Fatalf("got %s/%s, want %s/%s", d.Effect, d.Reason, tc.Expect.Effect, tc.Expect.Reason)
			}
		})
	}
}

func TestVectors_Capability(t *testing.T) {
	v, c := loadVectors(t)
	for _, tc := range v.Capability {
		t.Run(tc.Name, func(t *testing.T) {
			if got := c.HasCapability(tc.Subject, tc.Permission); got != tc.Expect {
				t.Fatalf("got %v, want %v", got, tc.Expect)
			}
		})
	}
}

func TestVectors_PermissionsForRoles(t *testing.T) {
	v, c := loadVectors(t)
	for _, tc := range v.PermissionsForRoles {
		t.Run(tc.Name, func(t *testing.T) {
			if got := c.PermissionsForRoles(tc.Roles...); !slices.Equal(got, tc.Expect) {
				t.Fatalf("got %v, want %v", got, tc.Expect)
			}
		})
	}
}

// The vectors catalog is the test catalog, so the two files cannot drift apart.
func TestVectors_CatalogMatchesTheTestCatalog(t *testing.T) {
	_, c := loadVectors(t)
	if d := rbac.Diff(c, testCatalog(t)); len(d) != 0 {
		t.Fatalf("vectors catalog differs from the test catalog: %v", d)
	}
}
