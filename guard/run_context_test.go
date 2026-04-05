package guard

import (
	"context"
	"testing"
)

func TestContextWithRunOptionsAppliesSessionLineage(t *testing.T) {
	g := New()
	ctx := ContextWithRunOptions(
		context.Background(),
		WithSessionID("ctx-session"),
		WithParentSessionID("ctx-parent"),
	)

	if _, err := g.Run(ctx, "Read", nil, nopCallable); err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := g.LocalSink().Events()
	if len(events) < 2 {
		t.Fatalf("events len = %d, want at least 2", len(events))
	}
	for _, event := range events {
		if event.SessionID != "ctx-session" {
			t.Fatalf("SessionID = %q, want %q", event.SessionID, "ctx-session")
		}
		if event.ParentSessionID != "ctx-parent" {
			t.Fatalf("ParentSessionID = %q, want %q", event.ParentSessionID, "ctx-parent")
		}
	}
}

func TestContextWithDefaultRunOptionsPreservesExistingValues(t *testing.T) {
	g := New()
	ctx := ContextWithRunOptions(context.Background(), WithSessionID("ctx-session"))
	ctx = ContextWithDefaultRunOptions(
		ctx,
		WithSessionID("default-session"),
		WithParentSessionID("default-parent"),
	)

	if _, err := g.Run(ctx, "Read", nil, nopCallable); err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := g.LocalSink().Events()
	if len(events) < 2 {
		t.Fatalf("events len = %d, want at least 2", len(events))
	}
	for _, event := range events {
		if event.SessionID != "ctx-session" {
			t.Fatalf("SessionID = %q, want %q", event.SessionID, "ctx-session")
		}
		if event.ParentSessionID != "default-parent" {
			t.Fatalf("ParentSessionID = %q, want %q", event.ParentSessionID, "default-parent")
		}
	}
}
