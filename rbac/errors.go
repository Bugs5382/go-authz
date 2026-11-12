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
	"errors"

	"github.com/Bugs5382/go-apperr"
)

// CodeBand is the leading digit of every code this package emits, so its codes
// stay apart from a service's own bands.
const CodeBand = 9

// The codes this package attaches to the errors it returns. 9002 is not used.
const (
	CodeDenied            = 9001
	CodeUnknownPermission = 9003
	CodeUnknownRole       = 9004
	CodeInvalidCatalog    = 9005
)

// Sentinel errors, matched with errors.Is. Each one reaches a caller wrapped in
// its code (see Entries).
var (
	ErrDenied            = errors.New("authz: access denied")
	ErrUnknownPermission = errors.New("authz: unknown permission")
	ErrUnknownRole       = errors.New("authz: unknown role")
	ErrInvalidCatalog    = errors.New("authz: invalid permission catalog")
)

func unknownPermission(s string) error {
	return apperr.WithMeta(apperr.Coded(CodeUnknownPermission, ErrUnknownPermission), apperr.Meta("permission", s))
}

func unknownRole(s string) error {
	return apperr.WithMeta(apperr.Coded(CodeUnknownRole, ErrUnknownRole), apperr.Meta("role", s))
}

// Entries returns the go-apperr entries for this package's codes. A service
// adds them to the registry it builds at startup, so a coded error from here
// presents with the right category, symbol and user-safe message.
func Entries() []apperr.Entry {
	return []apperr.Entry{
		{
			Code: CodeDenied, Symbol: "AUTHZ_DENIED", Category: apperr.CategoryPermissionDenied,
			Title: "authz", Cause: "the access decision denied the request",
			UserSafe: true, Message: "You don't have permission to do that.",
		},
		{
			Code: CodeUnknownPermission, Symbol: "AUTHZ_UNKNOWN_PERMISSION", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a permission name is not in the catalog",
			UserSafe: true, Message: "{permission} is not a known permission.",
		},
		{
			Code: CodeUnknownRole, Symbol: "AUTHZ_UNKNOWN_ROLE", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a role name is not in the catalog",
			UserSafe: true, Message: "{role} is not a known role.",
		},
		{
			Code: CodeInvalidCatalog, Symbol: "AUTHZ_INVALID_CATALOG", Category: apperr.CategoryInvalid,
			Title: "authz", Cause: "a permission catalog failed validation",
			UserSafe: false, Message: "The permission catalog is not valid ({problem}).",
		},
	}
}
