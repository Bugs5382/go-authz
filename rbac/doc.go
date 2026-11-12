// Package rbac is a permission catalog: the mechanism that turns roles,
// scoped grants and per-resource overrides into an access decision for one
// named permission.
//
// The package holds no permission, role or wording of its own. A service
// writes its catalog as a JSON file, embeds it with go:embed and loads it
// once with [Parse], [Load] or [MustParse]. The catalog lists the permissions
// ("<resource>.<verb>", some of them scoped to categories), the roles and the
// permissions each role holds, and names the permission that means "read",
// the one that means "read sensitive", the roles that bypass a scope and the
// roles that see an excluded resource obfuscated.
//
// [Catalog.HasCapability] is the coarse check: could the subject be allowed a
// permission in at least one scope. [Catalog.Authorize] decides one permission
// for a [Subject] on a [Resource]: the capability gate, then category scope
// for a scoped permission (a grant on a category covers every category below
// it), then, for a read, overrides, break-glass and sensitivity. See the
// Authorize documentation for the exact order.
//
// rbac does not evaluate category rules; that is the ordered package. It does
// no I/O and keeps no state, so every call is safe for concurrent use as long
// as the Catalog is not modified. A parsed Catalog is plain data: treat it as
// read-only.
//
// Errors carry go-apperr codes, see [Entries].
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
