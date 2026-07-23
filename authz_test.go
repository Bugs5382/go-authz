package authz_test

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
	"context"
	"log/slog"
	"strings"
	"testing"

	authz "github.com/Bugs5382/go-authz"
)

func TestEffectString(t *testing.T) {
	t.Parallel()
	if authz.Allow.String() != "allow" || authz.Deny.String() != "deny" {
		t.Fatalf("unexpected effect strings: %q %q", authz.Allow, authz.Deny)
	}
	if authz.Effect(0).String() != "deny" {
		t.Fatal("zero value must stringify as deny")
	}
}

func TestDefaultDenyAll(t *testing.T) {
	t.Parallel()
	p := authz.NewPolicy()
	d := p.Decide(context.Background(), authz.Request{Subject: "a", Resource: "r", Action: "x"})
	if d.Allowed() {
		t.Fatal("empty policy must deny")
	}
	if d.Effect != authz.Deny || d.Reason != authz.ReasonNoMatch || d.RuleID != "" {
		t.Fatalf("unexpected default decision: %+v", d)
	}
}

func TestFirstApplicableOrdering(t *testing.T) {
	t.Parallel()
	p := authz.NewPolicy().Add(
		authz.DenyWhen("deny-x", authz.ActionIs("x")),
		authz.AllowWhen("allow-x", authz.ActionIs("x")),
	)
	d := p.Decide(context.Background(), authz.Request{Action: "x"})
	if d.Allowed() || d.RuleID != "deny-x" || d.Reason != authz.ReasonRuleMatched {
		t.Fatalf("first applicable should pick deny-x: %+v", d)
	}
}

func TestDenyOverrides(t *testing.T) {
	t.Parallel()
	p := authz.NewPolicy(authz.WithCombiner(authz.DenyOverrides)).Add(
		authz.AllowWhen("a", authz.ActionIs("x")),
		authz.DenyWhen("d", authz.ActionIs("x")),
	)
	d := p.Decide(context.Background(), authz.Request{Action: "x"})
	if d.Allowed() || d.RuleID != "d" {
		t.Fatalf("deny must override allow: %+v", d)
	}
}

func TestAllowOverrides(t *testing.T) {
	t.Parallel()
	p := authz.NewPolicy(authz.WithCombiner(authz.AllowOverrides)).Add(
		authz.DenyWhen("d", authz.ActionIs("x")),
		authz.AllowWhen("a", authz.ActionIs("x")),
	)
	d := p.Decide(context.Background(), authz.Request{Action: "x"})
	if !d.Allowed() || d.RuleID != "a" {
		t.Fatalf("allow must override deny: %+v", d)
	}
}

func TestWithDefaultEffectAllow(t *testing.T) {
	t.Parallel()
	p := authz.NewPolicy(authz.WithDefaultEffect(authz.Allow))
	d := p.Decide(context.Background(), authz.Request{Action: "anything"})
	if !d.Allowed() || d.Reason != authz.ReasonNoMatch {
		t.Fatalf("default allow expected: %+v", d)
	}
}

func TestMatchers(t *testing.T) {
	t.Parallel()
	m := authz.All(authz.SubjectIs("alice"), authz.Any(authz.ActionIs("read"), authz.ActionIs("write")))
	ctx := context.Background()
	if !m(ctx, authz.Request{Subject: "alice", Action: "write"}) {
		t.Fatal("expected match")
	}
	if m(ctx, authz.Request{Subject: "bob", Action: "write"}) {
		t.Fatal("wrong subject must not match")
	}
	if m(ctx, authz.Request{Subject: "alice", Action: "delete"}) {
		t.Fatal("wrong action must not match")
	}
	if !authz.All()(ctx, authz.Request{}) {
		t.Fatal("empty All matches everything")
	}
	if authz.Any()(ctx, authz.Request{}) {
		t.Fatal("empty Any matches nothing")
	}
	if !authz.ResourceIs("doc")(ctx, authz.Request{Resource: "doc"}) {
		t.Fatal("ResourceIs failed")
	}
}

func TestRBAC(t *testing.T) {
	t.Parallel()
	rbac := authz.NewRBAC("rbac").
		Assign("alice", "editor").
		Assign("bob", "viewer").
		Grant("editor", authz.Wildcard, "write").
		Grant("viewer", "report", "read")
	p := authz.NewPolicy().Add(rbac)
	ctx := context.Background()

	if d := p.Decide(ctx, authz.Request{Subject: "alice", Resource: "post", Action: "write"}); !d.Allowed() || d.RuleID != "rbac" {
		t.Fatalf("editor should write any resource: %+v", d)
	}
	if d := p.Decide(ctx, authz.Request{Subject: "bob", Resource: "report", Action: "read"}); !d.Allowed() {
		t.Fatal("viewer should read report")
	}
	if d := p.Decide(ctx, authz.Request{Subject: "bob", Resource: "post", Action: "read"}); d.Allowed() {
		t.Fatal("viewer must not read other resources")
	}
	if d := p.Decide(ctx, authz.Request{Subject: "carol", Resource: "report", Action: "read"}); d.Allowed() {
		t.Fatal("unknown subject must be denied")
	}
}

func TestMatrixSpecificity(t *testing.T) {
	t.Parallel()
	m := authz.NewMatrix("access").
		Allow(authz.Wildcard, "document", "view"). // anyone may view
		Allow("editor1", "document", "edit").      // specific editor
		Deny("editor1", "document", "delete").     // editor cannot delete
		Allow("admin1", "document", "delete")
	p := authz.NewPolicy().Add(m)
	ctx := context.Background()

	if d := p.Decide(ctx, authz.Request{Subject: "anyone", Resource: "document", Action: "view"}); !d.Allowed() {
		t.Fatal("wildcard view should allow")
	}
	if d := p.Decide(ctx, authz.Request{Subject: "editor1", Resource: "document", Action: "delete"}); d.Allowed() {
		t.Fatal("editor delete must be denied")
	}
	if d := p.Decide(ctx, authz.Request{Subject: "admin1", Resource: "document", Action: "delete"}); !d.Allowed() {
		t.Fatal("admin should delete")
	}
	if d := p.Decide(ctx, authz.Request{Subject: "x", Resource: "document", Action: "edit"}); d.Allowed() {
		t.Fatal("non-editor must not edit")
	}
}

func TestMatrixMostSpecificWinsOverWildcard(t *testing.T) {
	t.Parallel()
	m := authz.NewMatrix("m").
		Allow(authz.Wildcard, "r", "a").
		Deny("blocked", "r", "a")
	p := authz.NewPolicy().Add(m)
	if p.Decide(context.Background(), authz.Request{Subject: "blocked", Resource: "r", Action: "a"}).Allowed() {
		t.Fatal("specific deny must win over wildcard allow")
	}
}

func TestRequestAttr(t *testing.T) {
	t.Parallel()
	owns := authz.AllowWhen("owner", func(_ context.Context, req authz.Request) bool {
		v, ok := req.Attr("owner")
		return ok && v == req.Subject
	})
	p := authz.NewPolicy().Add(owns)
	ctx := context.Background()
	if !p.Decide(ctx, authz.Request{Subject: "alice", Attributes: map[string]any{"owner": "alice"}}).Allowed() {
		t.Fatal("owner should be allowed")
	}
	if p.Decide(ctx, authz.Request{Subject: "alice", Attributes: map[string]any{"owner": "bob"}}).Allowed() {
		t.Fatal("non-owner should be denied")
	}
}

func TestLogger(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := authz.NewPolicy(authz.WithLogger(logger))
	p.Decide(context.Background(), authz.Request{Subject: "s", Resource: "r", Action: "a"})
	out := buf.String()
	if !strings.Contains(out, "authz decision") || !strings.Contains(out, "effect=deny") {
		t.Fatalf("expected decision log, got: %q", out)
	}
}

func TestEvaluatorInterface(t *testing.T) {
	t.Parallel()
	var e authz.Evaluator = authz.NewPolicy()
	if e.Decide(context.Background(), authz.Request{}).Allowed() {
		t.Fatal("interface decide should deny by default")
	}
}
