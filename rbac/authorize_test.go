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
	"errors"
	"testing"

	"github.com/Bugs5382/go-apperr"

	"github.com/Bugs5382/go-authz/rbac"
)

func TestAuthorize_Capability(t *testing.T) {
	c := testCatalog(t)
	if d := c.Authorize(roles("viewer"), "doc.write", &rbac.Resource{Category: "Finance"}); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonMissingCapability {
		t.Fatalf("viewer write: %+v", d)
	}
	bob := rbac.Subject{UserID: "bob", Roles: []rbac.Role{"editor"}, ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Finance"}}}
	if d := c.Authorize(bob, "doc.write", &rbac.Resource{Category: "Finance"}); d.Effect != rbac.EffectAllow {
		t.Fatalf("editor in scope: %+v", d)
	}
	if d := c.Authorize(bob, "doc.write", &rbac.Resource{Category: "People"}); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonOutOfScope {
		t.Fatalf("editor out of scope: %+v", d)
	}
}

func TestAuthorize_ScopedActionWithoutResourceIsOutOfScope(t *testing.T) {
	c := testCatalog(t)
	bob := rbac.Subject{ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Finance"}}}
	if d := c.Authorize(bob, "doc.write", nil); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonOutOfScope {
		t.Fatalf("scoped action with no resource: %+v", d)
	}
}

func TestAuthorize_BypassRoleAuthorsEverywhereButPublishesOnlyWithAGrant(t *testing.T) {
	c := testCatalog(t)
	res := &rbac.Resource{Category: "Finance", CategoryLineage: []string{"Finance"}}
	if d := c.Authorize(roles("superuser"), "doc.publish", res); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonOutOfScope {
		t.Fatalf("superuser publish without a grant must deny: %+v", d)
	}
	alice := rbac.Subject{Roles: []rbac.Role{"superuser"}, ScopedGrants: []rbac.ScopedGrant{{Role: "reviewer", Category: "Finance"}}}
	if d := c.Authorize(alice, "doc.publish", res); d.Effect != rbac.EffectAllow {
		t.Fatalf("superuser publish with a grant must allow: %+v", d)
	}
	for _, p := range []rbac.Permission{"doc.write", "doc.submit"} {
		if d := c.Authorize(roles("superuser"), p, res); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonGranted {
			t.Fatalf("superuser %s: %+v", p, d)
		}
	}
	carol := rbac.Subject{ScopedGrants: []rbac.ScopedGrant{{Role: "reviewer", Category: "Finance"}}}
	if d := c.Authorize(carol, "doc.publish", res); d.Effect != rbac.EffectAllow {
		t.Fatalf("scoped reviewer: %+v", d)
	}
}

func TestAuthorize_BypassNeedsTheCapabilityFirst(t *testing.T) {
	c := testCatalog(t)
	// A subject whose role bypasses scope but does not hold the permission is denied on capability.
	for i := range c.Roles {
		if c.Roles[i].Name == "superuser" {
			c.Roles[i].Permissions = []rbac.Permission{"doc.read"}
		}
	}
	d := c.Authorize(roles("superuser"), "doc.write", &rbac.Resource{Category: "X"})
	if d.Reason != rbac.ReasonMissingCapability {
		t.Fatalf("got %+v", d)
	}
}

func TestAuthorize_ScopedGrantInheritsDownTheTree(t *testing.T) {
	c := testCatalog(t)
	bob := rbac.Subject{ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Workplace"}}}
	child := &rbac.Resource{Category: "Facilities", CategoryLineage: []string{"Facilities", "Workplace"}}
	if d := c.Authorize(bob, "doc.write", child); d.Effect != rbac.EffectAllow {
		t.Fatalf("a grant on the parent covers the child: %+v", d)
	}
	self := &rbac.Resource{Category: "Workplace", CategoryLineage: []string{"Workplace"}}
	if d := c.Authorize(bob, "doc.write", self); d.Effect != rbac.EffectAllow {
		t.Fatalf("a grant on the parent covers the parent: %+v", d)
	}
	sibling := &rbac.Resource{Category: "Expenses", CategoryLineage: []string{"Expenses", "Finance"}}
	if d := c.Authorize(bob, "doc.write", sibling); d.Effect != rbac.EffectDeny {
		t.Fatalf("a grant must not cover a category outside its subtree: %+v", d)
	}
	if d := c.Authorize(bob, "doc.publish", child); d.Effect != rbac.EffectDeny {
		t.Fatalf("an editor grant must not satisfy publish: %+v", d)
	}
}

func TestAuthorize_LineageFallsBackToTheCategory(t *testing.T) {
	c := testCatalog(t)
	bob := rbac.Subject{ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Travel"}}}
	if d := c.Authorize(bob, "doc.submit", &rbac.Resource{Category: "Travel"}); d.Effect != rbac.EffectAllow {
		t.Fatalf("with no lineage the category itself is matched: %+v", d)
	}
}

func TestHasCapability(t *testing.T) {
	c := testCatalog(t)
	if !c.HasCapability(roles("superuser"), "doc.publish") {
		t.Fatal("superuser publish")
	}
	if c.HasCapability(roles("viewer"), "doc.publish") {
		t.Fatal("viewer publish")
	}
	carol := rbac.Subject{ScopedGrants: []rbac.ScopedGrant{{Role: "reviewer", Category: "Finance"}}}
	if !c.HasCapability(carol, "doc.publish") {
		t.Fatal("a scoped-only reviewer holds the publish capability")
	}
	if c.HasCapability(carol, "template.manage") {
		t.Fatal("a scoped reviewer must not hold template.manage")
	}
	if !c.HasCapability(rbac.Subject{ReadSensitive: true}, "doc.read_sensitive") {
		t.Fatal("the individual grant confers the sensitive-read capability without a role")
	}
	if c.HasCapability(rbac.Subject{ReadSensitive: true}, "audit.read") {
		t.Fatal("the individual grant confers nothing else")
	}
}

func TestAuthorize_GlobalCapability(t *testing.T) {
	c := testCatalog(t)
	frank := roles("designer")
	if d := c.Authorize(frank, "template.manage", nil); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonGranted {
		t.Fatalf("designer template.manage: %+v", d)
	}
	if d := c.Authorize(frank, "audit.read", nil); d.Effect != rbac.EffectDeny {
		t.Fatalf("designer audit.read: %+v", d)
	}
}

func TestAuthorize_Visibility(t *testing.T) {
	c := testCatalog(t)
	pub := &rbac.Resource{ID: "DOC-1", Category: "Facilities"}
	if d := c.Authorize(roles("viewer"), "doc.read", pub); d.Effect != rbac.EffectAllow {
		t.Fatalf("viewer read: %+v", d)
	}
	if d := c.Authorize(rbac.Subject{}, "doc.read", nil); d.Effect != rbac.EffectAllow {
		t.Fatalf("a read with no resource is the capability check alone: %+v", d)
	}

	erin := roles("viewer")
	erin.BreakGlass = map[string]bool{"DOC-1": true}
	if d := c.Authorize(erin, "doc.read", pub); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonBreakGlass {
		t.Fatalf("break glass: %+v", d)
	}

	sens := &rbac.Resource{ID: "DOC-2", Category: "Expenses", Sensitive: true}
	if d := c.Authorize(roles("viewer"), "doc.read", sens); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonSensitive {
		t.Fatalf("sensitive without clearance: %+v", d)
	}
	if d := c.Authorize(rbac.Subject{Roles: []rbac.Role{"viewer"}, ReadSensitive: true}, "doc.read", sens); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonGranted {
		t.Fatalf("sensitive with the individual grant: %+v", d)
	}

	ov := rbac.Subject{Roles: []rbac.Role{"viewer"}, Overrides: []rbac.Override{{ResourceID: "DOC-2", Grant: rbac.GrantAllow}}}
	if d := c.Authorize(ov, "doc.read", sens); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonOverrideAllow {
		t.Fatalf("an override allow grants read whatever else would deny: %+v", d)
	}

	alice := rbac.Subject{Roles: []rbac.Role{"superuser"}, Overrides: []rbac.Override{{ResourceID: "DOC-1", Grant: rbac.GrantDeny}}}
	if d := c.Authorize(alice, "doc.read", pub); d.Effect != rbac.EffectObfuscate || d.Reason != rbac.ReasonExcluded {
		t.Fatalf("an override deny on an obfuscate role obfuscates: %+v", d)
	}
	excluded := rbac.Subject{Overrides: []rbac.Override{{ResourceID: "DOC-1", Grant: rbac.GrantDeny}}}
	if d := c.Authorize(excluded, "doc.read", pub); d.Effect != rbac.EffectDeny || d.Reason != rbac.ReasonExcluded {
		t.Fatalf("an override deny hides the resource from anyone else: %+v", d)
	}
	blank := rbac.Subject{Overrides: []rbac.Override{{ResourceID: "DOC-1", Grant: rbac.GrantBlank}}}
	if d := c.Authorize(blank, "doc.read", pub); d.Effect != rbac.EffectAllow || d.Reason != rbac.ReasonGranted {
		t.Fatalf("a blank override has no opinion: %+v", d)
	}
	other := rbac.Subject{Overrides: []rbac.Override{{ResourceID: "DOC-9", Grant: rbac.GrantDeny}}}
	if d := c.Authorize(other, "doc.read", pub); d.Effect != rbac.EffectAllow {
		t.Fatalf("an override on another resource does not apply: %+v", d)
	}
}

func TestDecision_Allowed(t *testing.T) {
	if !(rbac.Decision{Effect: rbac.EffectAllow}).Allowed() {
		t.Fatal("allow is allowed")
	}
	for _, e := range []rbac.Effect{rbac.EffectDeny, rbac.EffectObfuscate, ""} {
		if (rbac.Decision{Effect: e}).Allowed() {
			t.Fatalf("%q must not be allowed", e)
		}
	}
}

func TestDecision_Err(t *testing.T) {
	c := testCatalog(t)
	if err := c.Authorize(roles("viewer"), "doc.read", nil).Err(); err != nil {
		t.Fatalf("an allow has no error, got %v", err)
	}
	err := c.Authorize(roles("viewer"), "audit.read", nil).Err()
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if code, ok := apperr.Code(err); !ok || code != rbac.CodeDenied {
		t.Fatalf("want code %d, got %d (%v)", rbac.CodeDenied, code, ok)
	}
	if md := apperr.Metadata(err); len(md) != 0 {
		t.Fatalf("a denial must not send its reason to the client, got %v", md)
	}
	if err := (rbac.Decision{Effect: rbac.EffectObfuscate, Reason: rbac.ReasonExcluded}).Err(); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an obfuscate is not an allow: %v", err)
	}
}

func TestAuthorize_SensitiveReadIsAssignmentOrExplicitGrantOnly(t *testing.T) {
	c := testCatalog(t)
	doc := &rbac.Resource{
		ID: "DOC-2", Category: "Expenses", CategoryLineage: []string{"Expenses", "Finance"},
		Sensitive: true, Authors: []string{"bob"}, Approvers: []string{"carol"},
	}
	scopedEditor := func(id string) rbac.Subject {
		return rbac.Subject{UserID: id, Roles: []rbac.Role{"editor"}, ScopedGrants: []rbac.ScopedGrant{{Role: "editor", Category: "Finance"}}}
	}
	scopedReviewer := func(id string) rbac.Subject {
		return rbac.Subject{UserID: id, Roles: []rbac.Role{"reviewer"}, ScopedGrants: []rbac.ScopedGrant{{Role: "reviewer", Category: "Finance"}}}
	}
	cases := []struct {
		name   string
		s      rbac.Subject
		effect rbac.Effect
		reason rbac.Reason
	}{
		{"the assigned author", scopedEditor("bob"), rbac.EffectAllow, rbac.ReasonAssigned},
		{"the assigned approver", scopedReviewer("carol"), rbac.EffectAllow, rbac.ReasonAssigned},
		{"an assigned author with no role", rbac.Subject{UserID: "bob"}, rbac.EffectAllow, rbac.ReasonAssigned},
		{"an unassigned editor of the category", scopedEditor("dave"), rbac.EffectDeny, rbac.ReasonSensitive},
		{"an unassigned reviewer of the category", scopedReviewer("heidi"), rbac.EffectDeny, rbac.ReasonSensitive},
		{"the individual grant", rbac.Subject{UserID: "frank", ReadSensitive: true}, rbac.EffectAllow, rbac.ReasonGranted},
		{"an override allow on this document", rbac.Subject{UserID: "frank", Overrides: []rbac.Override{{ResourceID: "DOC-2", Grant: rbac.GrantAllow}}}, rbac.EffectAllow, rbac.ReasonOverrideAllow},
		{"a break-glass grant on this document", rbac.Subject{UserID: "frank", BreakGlass: map[string]bool{"DOC-2": true}}, rbac.EffectAllow, rbac.ReasonBreakGlass},
		{"an auditor", rbac.Subject{UserID: "grace", Roles: []rbac.Role{"auditor"}}, rbac.EffectDeny, rbac.ReasonSensitive},
		{"a superuser", rbac.Subject{UserID: "alice", Roles: []rbac.Role{"superuser"}}, rbac.EffectDeny, rbac.ReasonSensitive},
		{"a viewer", rbac.Subject{UserID: "erin"}, rbac.EffectDeny, rbac.ReasonSensitive},
		{"a subject with no user id", rbac.Subject{}, rbac.EffectDeny, rbac.ReasonSensitive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := c.Authorize(tc.s, "doc.read", doc)
			if d.Effect != tc.effect || d.Reason != tc.reason {
				t.Fatalf("got %+v, want %s/%s", d, tc.effect, tc.reason)
			}
		})
	}
}

func TestAuthorize_NoUserIDNeverMatchesAnEmptyAssignment(t *testing.T) {
	c := testCatalog(t)
	doc := &rbac.Resource{ID: "DOC-3", Sensitive: true, Authors: []string{""}}
	if d := c.Authorize(rbac.Subject{}, "doc.read", doc); d.Effect != rbac.EffectDeny {
		t.Fatalf("an empty user id must not match an empty assignment: %+v", d)
	}
}

func TestAuthorize_UnknownPermissionIsUnscoped(t *testing.T) {
	c := testCatalog(t)
	if d := c.Authorize(roles("superuser"), "report.export", nil); d.Effect != rbac.EffectAllow {
		t.Fatalf("a wildcard role is allowed a permission added later: %+v", d)
	}
	if d := c.Authorize(roles("auditor"), "report.export", nil); d.Reason != rbac.ReasonMissingCapability {
		t.Fatalf("got %+v", d)
	}
}

func TestAuthorize_NoSensitivePermissionReadsStayOpenToGrantHolders(t *testing.T) {
	// The sensitive permission as the asked permission is a plain capability check.
	c := testCatalog(t)
	if d := c.Authorize(rbac.Subject{ReadSensitive: true}, "doc.read_sensitive", nil); d.Effect != rbac.EffectAllow {
		t.Fatalf("%+v", d)
	}
	if d := c.Authorize(roles("superuser"), "doc.read_sensitive", nil); d.Reason != rbac.ReasonMissingCapability {
		t.Fatalf("%+v", d)
	}
}
