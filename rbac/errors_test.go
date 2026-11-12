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
	"testing"

	"github.com/Bugs5382/go-apperr"

	"github.com/Bugs5382/go-authz/rbac"
)

func TestEntries_FormAValidRegistry(t *testing.T) {
	reg, err := apperr.NewRegistry(rbac.Entries(), apperr.WithService(rbac.CodeBand), apperr.WithCodeDigits(4))
	if err != nil {
		t.Fatalf("the library's codes must form a valid registry: %v", err)
	}
	for _, c := range []int{rbac.CodeDenied, rbac.CodeUnknownPermission, rbac.CodeUnknownRole, rbac.CodeInvalidCatalog} {
		e, ok := reg.Describe(c)
		if !ok || e.Symbol == "" {
			t.Errorf("code %d: registered=%v symbol=%q", c, ok, e.Symbol)
		}
	}
}

func TestCodes_AreStable(t *testing.T) {
	if rbac.CodeDenied != 9001 || rbac.CodeUnknownPermission != 9003 || rbac.CodeUnknownRole != 9004 || rbac.CodeInvalidCatalog != 9005 {
		t.Fatal("codes are part of the wire contract; change them only on purpose")
	}
}

func TestEntries_Categories(t *testing.T) {
	reg, err := apperr.NewRegistry(rbac.Entries())
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]apperr.Category{
		rbac.CodeDenied:            apperr.CategoryPermissionDenied,
		rbac.CodeUnknownPermission: apperr.CategoryInvalid,
		rbac.CodeUnknownRole:       apperr.CategoryInvalid,
		rbac.CodeInvalidCatalog:    apperr.CategoryInvalid,
	}
	for code, cat := range want {
		if got := reg.Category(apperr.Coded(code, nil)); got != cat {
			t.Errorf("code %d category = %v, want %v", code, got, cat)
		}
	}
}

func TestEntries_PresentUserSafeMessages(t *testing.T) {
	reg, err := apperr.NewRegistry(rbac.Entries())
	if err != nil {
		t.Fatal(err)
	}
	c := testCatalog(t)
	_, perr := c.ParsePermission("doc.delete")
	msg, code := reg.Present(perr, 0)
	if code != rbac.CodeUnknownPermission || msg != "doc.delete is not a known permission." {
		t.Fatalf("Present = %q, %d", msg, code)
	}
	_, rerr := c.ParseRole("admin")
	if msg, _ = reg.Present(rerr, 0); msg != "admin is not a known role." {
		t.Fatalf("role message = %q", msg)
	}
	msg, _ = reg.Present(c.Authorize(rbac.Subject{}, "audit.read", nil).Err(), 0)
	if msg != "You don't have permission to do that." {
		t.Fatalf("denied message = %q", msg)
	}
}
