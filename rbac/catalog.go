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
	"slices"
	"strings"
)

// Wildcard in a role's permission list stands for every permission in the
// catalog, and for any permission added to it later, except the sensitive
// read, which no role ever holds.
const Wildcard = "*"

// Permission is one entry of the catalog, written "<resource>.<verb>".
type Permission string

// Resource is the part before the first dot ("doc" in "doc.read").
func (p Permission) Resource() string {
	r, _, _ := strings.Cut(string(p), ".")
	return r
}

// Verb is the part after the first dot ("read" in "doc.read").
func (p Permission) Verb() string {
	_, v, _ := strings.Cut(string(p), ".")
	return v
}

// Role is a named bundle of permissions.
type Role string

// PermissionDef declares one permission of the catalog.
type PermissionDef struct {
	// Name is "<resource>.<verb>": lower-case letters, digits and underscores
	// around exactly one dot.
	Name Permission `json:"name"`
	// Scoped means the permission only takes effect inside the categories a
	// subject holds a scoped grant for, and the categories below them.
	Scoped bool `json:"scoped,omitempty"`
	// ScopeRole is the role a ScopedGrant must carry to confer this
	// permission. Required when Scoped, and the role must hold the permission.
	ScopeRole Role `json:"scopeRole,omitempty"`
	// BypassRoles hold this permission in every category without a grant.
	// They must still hold it through the role matrix.
	BypassRoles []Role `json:"bypassRoles,omitempty"`
}

// RoleDef declares one role and the permissions it holds.
type RoleDef struct {
	Name Role `json:"name"`
	// Permissions are permission names, or [Wildcard].
	Permissions []Permission `json:"permissions"`
}

// ReadConfig names the permissions the read decision is about.
type ReadConfig struct {
	// Permission is the permission that means "read a resource".
	Permission Permission `json:"permission"`
	// SensitivePermission is the permission that means "read every sensitive
	// resource". No role holds it, not even through the wildcard: it is an
	// individual grant, see Subject.ReadSensitive.
	SensitivePermission Permission `json:"sensitivePermission"`
	// ObfuscateRoles are the roles that, when a resource is excluded for them
	// by an override deny, may still see that it exists.
	ObfuscateRoles []Role `json:"obfuscateRoles,omitempty"`
}

// Catalog is the permission catalog: the data a service supplies. Load it with
// Parse, Load or MustParse, or build one in code and call Validate. Permission
// and role order is the order every listing reports.
type Catalog struct {
	// Version is the schema version, currently 1.
	Version int `json:"version"`
	// BaselineRole, when set, is held by every subject and never stored.
	BaselineRole Role            `json:"baselineRole,omitempty"`
	Read         ReadConfig      `json:"read"`
	Permissions  []PermissionDef `json:"permissions"`
	Roles        []RoleDef       `json:"roles"`
}

// PermissionNames returns every permission of the catalog, in catalog order.
func (c Catalog) PermissionNames() []Permission {
	out := make([]Permission, len(c.Permissions))
	for i, p := range c.Permissions {
		out[i] = p.Name
	}
	return out
}

// RoleNames returns every role of the catalog, in catalog order.
func (c Catalog) RoleNames() []Role {
	out := make([]Role, len(c.Roles))
	for i, r := range c.Roles {
		out[i] = r.Name
	}
	return out
}

func (c Catalog) permission(p Permission) (PermissionDef, bool) {
	for _, d := range c.Permissions {
		if d.Name == p {
			return d, true
		}
	}
	return PermissionDef{}, false
}

func (c Catalog) role(r Role) (RoleDef, bool) {
	for _, d := range c.Roles {
		if d.Name == r {
			return d, true
		}
	}
	return RoleDef{}, false
}

// ParsePermission checks a permission name read from outside (storage, a
// token, an admin form) against the catalog.
func (c Catalog) ParsePermission(s string) (Permission, error) {
	if _, ok := c.permission(Permission(s)); !ok {
		return "", unknownPermission(s)
	}
	return Permission(s), nil
}

// ParseRole checks a role name read from outside against the catalog.
func (c Catalog) ParseRole(s string) (Role, error) {
	if _, ok := c.role(Role(s)); !ok {
		return "", unknownRole(s)
	}
	return Role(s), nil
}

// IsScoped reports whether the permission only takes effect inside the
// categories a subject holds a scoped grant for. A permission outside the
// catalog is not scoped.
func (c Catalog) IsScoped(p Permission) bool {
	d, ok := c.permission(p)
	return ok && d.Scoped
}

// RoleHolds reports whether the role grants the permission on its own. A role
// holding the wildcard holds every permission, including ones not yet in the
// catalog, except the sensitive read. An unknown role holds nothing.
func (c Catalog) RoleHolds(r Role, p Permission) bool {
	d, ok := c.role(r)
	if !ok {
		return false
	}
	for _, g := range d.Permissions {
		if g == p || (g == Wildcard && p != c.Read.SensitivePermission) {
			return true
		}
	}
	return false
}

// RolePermissions returns the catalog permissions the role grants on its own,
// in catalog order. An unknown role grants nothing.
func (c Catalog) RolePermissions(r Role) []Permission {
	var out []Permission
	for _, d := range c.Permissions {
		if c.RoleHolds(r, d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// PermissionsForRoles returns the catalog permissions the given roles grant
// together, in catalog order. The baseline role is always included and an
// unknown role adds nothing.
func (c Catalog) PermissionsForRoles(rs ...Role) []Permission {
	all := rs
	if c.BaselineRole != "" {
		all = append(slices.Clone(rs), c.BaselineRole)
	}
	var out []Permission
	for _, d := range c.Permissions {
		if slices.ContainsFunc(all, func(r Role) bool { return c.RoleHolds(r, d.Name) }) {
			out = append(out, d.Name)
		}
	}
	return out
}
