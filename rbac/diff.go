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
)

// Diff compares two catalogs and returns one line per difference, sorted. The
// result is empty when the catalogs are equal. Order of permissions, roles and
// lists inside them is not a difference. A service uses it to check that its
// embedded copy still matches the canonical one.
func Diff(a, b Catalog) []string {
	var out []string
	field := func(name string, x, y any) {
		if fmt.Sprint(x) != fmt.Sprint(y) {
			out = append(out, fmt.Sprintf("%s: %v -> %v", name, x, y))
		}
	}
	field("version", a.Version, b.Version)
	field("baselineRole", a.BaselineRole, b.BaselineRole)
	field("read.permission", a.Read.Permission, b.Read.Permission)
	field("read.sensitivePermission", a.Read.SensitivePermission, b.Read.SensitivePermission)
	field("read.obfuscateRoles", sorted(a.Read.ObfuscateRoles), sorted(b.Read.ObfuscateRoles))

	for _, x := range a.Permissions {
		y, ok := b.permission(x.Name)
		if !ok {
			out = append(out, fmt.Sprintf("permission removed: %s", x.Name))
			continue
		}
		change := func(what string, from, to any) {
			if fmt.Sprint(from) != fmt.Sprint(to) {
				out = append(out, fmt.Sprintf("permission changed: %s %s %v -> %v", x.Name, what, from, to))
			}
		}
		change("scoped", x.Scoped, y.Scoped)
		change("scopeRole", x.ScopeRole, y.ScopeRole)
		change("bypassRoles", sorted(x.BypassRoles), sorted(y.BypassRoles))
	}
	for _, y := range b.Permissions {
		if _, ok := a.permission(y.Name); !ok {
			out = append(out, fmt.Sprintf("permission added: %s", y.Name))
		}
	}

	for _, x := range a.Roles {
		y, ok := b.role(x.Name)
		if !ok {
			out = append(out, fmt.Sprintf("role removed: %s", x.Name))
			continue
		}
		if from, to := sorted(x.Permissions), sorted(y.Permissions); !slices.Equal(from, to) {
			out = append(out, fmt.Sprintf("role changed: %s permissions %v -> %v", x.Name, from, to))
		}
	}
	for _, y := range b.Roles {
		if _, ok := a.role(y.Name); !ok {
			out = append(out, fmt.Sprintf("role added: %s", y.Name))
		}
	}

	slices.Sort(out)
	return out
}
