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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/Bugs5382/go-apperr"
)

// SchemaVersion is the catalog schema version this package reads.
const SchemaVersion = 1

var permissionName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

func invalidCatalog(problems ...string) error {
	joined := strings.Join(problems, "; ")
	return apperr.WithMeta(
		apperr.Coded(CodeInvalidCatalog, fmt.Errorf("%w: %s", ErrInvalidCatalog, joined)),
		apperr.Meta("problem", joined),
	)
}

// Parse reads a catalog from JSON and validates it. Unknown fields and data
// after the catalog are rejected. The error is coded CodeInvalidCatalog and
// lists every problem found.
func Parse(b []byte) (Catalog, error) { return Load(bytes.NewReader(b)) }

// Load is Parse for a reader, for example an embedded file.
func Load(r io.Reader) (Catalog, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return Catalog{}, invalidCatalog(err.Error())
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Catalog{}, invalidCatalog("data after the catalog")
	}
	if err := c.Validate(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// MustParse is Parse for a catalog fixed at build time, such as a package-level
// embed. It panics when the catalog is invalid.
func MustParse(b []byte) Catalog {
	c, err := Parse(b)
	if err != nil {
		panic(err)
	}
	return c
}

// Validate checks a catalog and reports every problem at once, as one error
// coded CodeInvalidCatalog. Parse and Load call it; call it yourself on a
// catalog built in code.
func (c Catalog) Validate() error {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	if c.Version != SchemaVersion {
		add("version must be %d, got %d", SchemaVersion, c.Version)
	}

	perms := map[Permission]bool{}
	for _, d := range c.Permissions {
		if !permissionName.MatchString(string(d.Name)) {
			add("permission name %q is not <resource>.<verb>", d.Name)
		}
		if perms[d.Name] {
			add("duplicate permission %q", d.Name)
		}
		perms[d.Name] = true
	}

	roles := map[Role]bool{}
	for _, d := range c.Roles {
		if d.Name == "" || strings.ContainsAny(string(d.Name), " \t\r\n*") {
			add("role name %q is empty or has whitespace or *", d.Name)
		}
		if roles[d.Name] {
			add("duplicate role %q", d.Name)
		}
		roles[d.Name] = true
	}

	for _, d := range c.Roles {
		seen := map[Permission]bool{}
		for _, p := range d.Permissions {
			switch {
			case seen[p]:
				add("role %q lists %s twice", d.Name, p)
			case p != Wildcard && !perms[p]:
				add("role %q lists unknown permission %q", d.Name, p)
			case p != "" && p == c.Read.SensitivePermission:
				add("role %q lists the sensitive permission %q; it is an individual grant only", d.Name, p)
			}
			seen[p] = true
		}
	}

	if c.BaselineRole != "" && !roles[c.BaselineRole] {
		add("baselineRole %q is not a role", c.BaselineRole)
	}

	for _, d := range c.Permissions {
		switch {
		case d.Scoped && d.ScopeRole == "":
			add("permission %q is scoped and needs a scopeRole", d.Name)
		case !d.Scoped && (d.ScopeRole != "" || len(d.BypassRoles) > 0):
			add("permission %q is not scoped but sets scopeRole or bypassRoles", d.Name)
		}
		if d.ScopeRole != "" {
			if !roles[d.ScopeRole] {
				add("permission %q: scopeRole %q is not a role", d.Name, d.ScopeRole)
			} else if !c.RoleHolds(d.ScopeRole, d.Name) {
				add("permission %q: scopeRole %q does not hold it", d.Name, d.ScopeRole)
			}
		}
		for _, r := range d.BypassRoles {
			if !roles[r] {
				add("permission %q: bypassRoles %q is not a role", d.Name, r)
			}
		}
	}

	c.validateRead(perms, roles, add)

	if len(problems) > 0 {
		return invalidCatalog(problems...)
	}
	return nil
}

func (c Catalog) validateRead(perms map[Permission]bool, roles map[Role]bool, add func(string, ...any)) {
	check := func(field string, p Permission) {
		switch {
		case p == "":
			add("%s is required", field)
		case !perms[p]:
			add("%s %q is not a permission", field, p)
		case c.IsScoped(p):
			add("%s %q must not be scoped", field, p)
		}
	}
	check("read.permission", c.Read.Permission)
	check("read.sensitivePermission", c.Read.SensitivePermission)
	if c.Read.Permission != "" && c.Read.Permission == c.Read.SensitivePermission {
		add("read.sensitivePermission must differ from read.permission")
	}
	for _, r := range c.Read.ObfuscateRoles {
		if !roles[r] {
			add("read.obfuscateRoles %q is not a role", r)
		}
	}
}

// sorted returns a sorted copy, for comparisons that ignore order.
func sorted[T ~string](in []T) []T {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
