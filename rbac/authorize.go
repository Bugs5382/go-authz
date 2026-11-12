package rbac

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
	"slices"

	"github.com/Bugs5382/go-apperr"
)

// Effect is the outcome of Authorize.
type Effect string

// The effects. Obfuscate means the subject may see that the resource exists,
// but not its content.
const (
	EffectDeny      Effect = "deny"
	EffectAllow     Effect = "allow"
	EffectObfuscate Effect = "obfuscate"
)

// Reason is a stable, machine-readable code for why a decision came out as it
// did, for decision logs and access simulators.
type Reason string

// The reasons Authorize returns.
const (
	ReasonGranted           Reason = "granted"
	ReasonMissingCapability Reason = "missing_capability"
	ReasonOutOfScope        Reason = "out_of_category_scope"
	ReasonOverrideAllow     Reason = "override_allow"
	ReasonBreakGlass        Reason = "break_glass"
	ReasonExcluded          Reason = "excluded"
	ReasonSensitive         Reason = "sensitive"
	ReasonAssigned          Reason = "assigned"
)

// Grant is the value of a per-resource override.
type Grant string

// The override values. A blank grant has no opinion.
const (
	GrantBlank Grant = ""
	GrantAllow Grant = "allow"
	GrantDeny  Grant = "deny"
)

// ScopedGrant gives a role inside one category and, through the category
// lineage, every category below it.
type ScopedGrant struct {
	Role     Role   `json:"role"`
	Category string `json:"category"`
}

// Override pins one resource for one subject: GrantAllow always shows it,
// GrantDeny excludes it.
type Override struct {
	ResourceID string `json:"resourceId"`
	Grant      Grant  `json:"grant"`
}

// Subject is the signed-in person a decision is made for.
type Subject struct {
	UserID string `json:"userId,omitempty"`
	Roles  []Role `json:"roles,omitempty"`
	// Groups and Root travel with the subject for callers and for other
	// engines; Authorize does not consult them.
	Groups       []string      `json:"groups,omitempty"`
	ScopedGrants []ScopedGrant `json:"scopedGrants,omitempty"`
	Overrides    []Override    `json:"overrides,omitempty"`
	// ReadSensitive is the individual grant of the catalog's sensitive read.
	ReadSensitive bool `json:"readSensitive,omitempty"`
	Root          bool `json:"root,omitempty"`
	// BreakGlass holds the resource IDs the subject has an active break-glass
	// grant for.
	BreakGlass map[string]bool `json:"breakGlass,omitempty"`
}

func (s Subject) override(id string) Grant {
	for _, o := range s.Overrides {
		if o.ResourceID == id {
			return o.Grant
		}
	}
	return GrantBlank
}

func (s Subject) hasAnyRole(rs []Role) bool {
	return slices.ContainsFunc(s.Roles, func(r Role) bool { return slices.Contains(rs, r) })
}

// Resource is what an action is aimed at.
type Resource struct {
	ID       string `json:"id,omitempty"`
	Category string `json:"category,omitempty"`
	// CategoryLineage is the category names from this resource's category up
	// to the root. When it is empty, Category alone is used.
	CategoryLineage []string `json:"categoryLineage,omitempty"`
	Sensitive       bool     `json:"sensitive,omitempty"`
	// Authors and Approvers are the user IDs assigned to this resource. On a
	// sensitive resource they are the only subjects, besides explicit grants,
	// who may read it.
	Authors   []string `json:"authors,omitempty"`
	Approvers []string `json:"approvers,omitempty"`
}

// Decision is the outcome of Authorize.
type Decision struct {
	Effect Effect `json:"effect"`
	Reason Reason `json:"reason"`
}

// Allowed reports whether the decision is a plain allow.
func (d Decision) Allowed() bool { return d.Effect == EffectAllow }

// Err returns nil for an allow, and otherwise an error coded CodeDenied that
// matches ErrDenied. The reason stays in the internal cause and is never put
// in the wire metadata.
func (d Decision) Err() error {
	if d.Allowed() {
		return nil
	}
	return apperr.Coded(CodeDenied, fmt.Errorf("%w: %s", ErrDenied, d.Reason))
}

// scopedIn reports whether the subject holds the permission's scope in any
// category of the lineage. A bypass role holds it everywhere; otherwise a
// scoped grant carrying the permission's scope role is needed.
func (c Catalog) scopedIn(s Subject, d PermissionDef, lineage []string) bool {
	if s.hasAnyRole(d.BypassRoles) {
		return true
	}
	return slices.ContainsFunc(s.ScopedGrants, func(g ScopedGrant) bool {
		return g.Role == d.ScopeRole && slices.Contains(lineage, g.Category)
	})
}

// HasCapability reports whether the subject could be allowed p in at least one
// scope: through the baseline role or a held role, the individual
// sensitive-read grant, or, for a scoped permission, any scoped grant whose
// role holds it. It is the coarse check for work that spans categories;
// Authorize makes the per-resource decision.
func (c Catalog) HasCapability(s Subject, p Permission) bool {
	if c.BaselineRole != "" && c.RoleHolds(c.BaselineRole, p) {
		return true
	}
	if slices.ContainsFunc(s.Roles, func(r Role) bool { return c.RoleHolds(r, p) }) {
		return true
	}
	if p == c.Read.SensitivePermission && s.ReadSensitive {
		return true
	}
	if c.IsScoped(p) {
		return slices.ContainsFunc(s.ScopedGrants, func(g ScopedGrant) bool { return c.RoleHolds(g.Role, p) })
	}
	return false
}

// Authorize decides p for the subject on r. r is nil for an action that is not
// aimed at one resource. The order is:
//
//  1. Without the capability (HasCapability): deny, missing_capability.
//  2. A scoped permission: with no resource, or no scope in the resource's
//     lineage, deny, out_of_category_scope; otherwise allow, granted. A bypass
//     role holds the scope everywhere.
//  3. Any permission other than the read permission, or a read with no
//     resource: allow, granted.
//  4. A read of a resource, first match wins: an override allow (allow,
//     override_allow); an override deny (obfuscate for an obfuscate role,
//     otherwise deny, both excluded); an active break-glass grant (allow,
//     break_glass); a sensitive resource without the individual grant (allow,
//     assigned for a user in Authors or Approvers, otherwise deny, sensitive);
//     otherwise allow, granted.
//
// A sensitive resource is therefore read only by its assigned authors and
// approvers and by explicit grants (the individual grant, an override allow,
// break-glass); no role reads it.
func (c Catalog) Authorize(s Subject, p Permission, r *Resource) Decision {
	if !c.HasCapability(s, p) {
		return Decision{EffectDeny, ReasonMissingCapability}
	}
	if d, ok := c.permission(p); ok && d.Scoped {
		if r == nil {
			return Decision{EffectDeny, ReasonOutOfScope}
		}
		lineage := r.CategoryLineage
		if len(lineage) == 0 {
			lineage = []string{r.Category}
		}
		if !c.scopedIn(s, d, lineage) {
			return Decision{EffectDeny, ReasonOutOfScope}
		}
		return Decision{EffectAllow, ReasonGranted}
	}
	if p != c.Read.Permission || r == nil {
		return Decision{EffectAllow, ReasonGranted}
	}
	switch s.override(r.ID) {
	case GrantAllow:
		return Decision{EffectAllow, ReasonOverrideAllow}
	case GrantDeny:
		if s.hasAnyRole(c.Read.ObfuscateRoles) {
			return Decision{EffectObfuscate, ReasonExcluded}
		}
		return Decision{EffectDeny, ReasonExcluded}
	}
	if s.BreakGlass[r.ID] {
		return Decision{EffectAllow, ReasonBreakGlass}
	}
	if r.Sensitive && !s.ReadSensitive {
		if s.UserID != "" && (slices.Contains(r.Authors, s.UserID) || slices.Contains(r.Approvers, s.UserID)) {
			return Decision{EffectAllow, ReasonAssigned}
		}
		return Decision{EffectDeny, ReasonSensitive}
	}
	return Decision{EffectAllow, ReasonGranted}
}
