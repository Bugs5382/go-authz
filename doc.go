// Package authz is a small, dependency-free, general-purpose authorization
// engine. The consuming application configures the model; nothing is hard-coded
// to a particular scheme.
//
// The building blocks are a Request (subject, resource, action, and optional
// attributes), a set of Rules, and a Policy that combines them into a Decision
// carrying an Effect (Allow or Deny) plus a machine-readable Reason for
// downstream logging. Deny is the zero value of Effect, so every unconfigured
// or unmatched path fails safe.
//
// The same engine expresses several common models:
//
//   - default-deny-all: NewPolicy() with no rules denies everything.
//   - allow / RBAC-style: assign subjects to roles and grant roles
//     (resource, action) permissions with RBAC, on a Deny default.
//   - responsibility matrix: a subject x resource x action table, with
//     per-dimension wildcards and most-specific-wins precedence, via Matrix.
//
// The package is framework-agnostic: it returns decisions and ships no
// HTTP/gRPC middleware. Optional decision logging uses the standard library
// log/slog only.
package authz

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
