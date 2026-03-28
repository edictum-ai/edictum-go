package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// --- Cat 6: Audit Event & Sinks ---

func TestEvent_SchemaVersion(t *testing.T) {
	e := NewEvent()
	if e.SchemaVersion != "0.3.0" {
		t.Fatalf("SchemaVersion = %q, want %q", e.SchemaVersion, "0.3.0")
	}
}

func TestEvent_Defaults(t *testing.T) {
	e := NewEvent()
	if e.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero")
	}
	if e.Mode != "enforce" {
		t.Fatalf("Mode = %q, want %q", e.Mode, "enforce")
	}
	if e.ToolSuccess != nil {
		t.Fatalf("ToolSuccess = %v, want nil", e.ToolSuccess)
	}
	if e.DurationMs != nil {
		t.Fatalf("DurationMs = %v, want nil", e.DurationMs)
	}
	if e.ToolArgs == nil {
		t.Fatal("ToolArgs should default to an empty map")
	}
	if e.HooksEvaluated == nil || e.RulesEvaluated == nil {
		t.Fatal("evaluated lists should default to non-nil slices")
	}
	if e.PolicyError {
		t.Fatal("PolicyError should be false by default")
	}
}

func TestAllActions_Count(t *testing.T) {
	actions := AllActions()
	if len(actions) != 10 {
		t.Fatalf("AllActions() returned %d actions, want 10", len(actions))
	}
}

func TestAllActions_Values(t *testing.T) {
	want := map[Action]bool{
		ActionCallDenied:            true,
		ActionCallWouldDeny:         true,
		ActionCallAllowed:           true,
		ActionCallExecuted:          true,
		ActionCallFailed:            true,
		ActionPostconditionWarning:  true,
		ActionCallApprovalRequested: true,
		ActionCallApprovalGranted:   true,
		ActionCallApprovalDenied:    true,
		ActionCallApprovalTimeout:   true,
	}
	for _, a := range AllActions() {
		if !want[a] {
			t.Fatalf("unexpected action %q", a)
		}
	}
}

func TestAllActions_StringValues(t *testing.T) {
	cases := []struct {
		action Action
		want   string
	}{
		{ActionCallDenied, "call_denied"},
		{ActionCallWouldDeny, "call_would_deny"},
		{ActionCallAllowed, "call_allowed"},
		{ActionCallExecuted, "call_executed"},
		{ActionCallFailed, "call_failed"},
		{ActionPostconditionWarning, "postcondition_warning"},
		{ActionCallApprovalRequested, "call_approval_requested"},
		{ActionCallApprovalGranted, "call_approval_granted"},
		{ActionCallApprovalDenied, "call_approval_denied"},
		{ActionCallApprovalTimeout, "call_approval_timeout"},
	}
	for _, tc := range cases {
		if string(tc.action) != tc.want {
			t.Errorf("Action %q != %q", tc.action, tc.want)
		}
	}
}

// --- CompositeSink ---

// countingSink tracks Emit calls.
type countingSink struct {
	mu    sync.Mutex
	count int
}

func (s *countingSink) Emit(_ context.Context, _ *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return nil
}

func (s *countingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// failingSink always returns an error.
type failingSink struct {
	err error
}

func (s *failingSink) Emit(_ context.Context, _ *Event) error {
	return s.err
}

type mutatingSink struct {
	mutate func(*Event)
}

func (s *mutatingSink) Emit(_ context.Context, event *Event) error {
	if s.mutate != nil {
		s.mutate(event)
	}
	return nil
}

type captureSink struct {
	last Event
}

func (s *captureSink) Emit(_ context.Context, event *Event) error {
	s.last = deepCopyEvent(*event)
	return nil
}

func TestCompositeSink_FanOut(t *testing.T) {
	s1 := &countingSink{}
	s2 := &countingSink{}
	s3 := &countingSink{}
	comp := NewCompositeSink(s1, s2, s3)

	e := NewEvent()
	e.Action = ActionCallAllowed
	if err := comp.Emit(context.Background(), &e); err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	if s1.Count() != 1 || s2.Count() != 1 || s3.Count() != 1 {
		t.Fatalf("counts = (%d, %d, %d), want (1, 1, 1)",
			s1.Count(), s2.Count(), s3.Count())
	}
}

func TestCompositeSink_AllSinksCalledOnError(t *testing.T) {
	s1 := &countingSink{}
	fail := &failingSink{err: fmt.Errorf("sink2 broke")}
	s3 := &countingSink{}
	comp := NewCompositeSink(s1, fail, s3)

	e := NewEvent()
	err := comp.Emit(context.Background(), &e)
	if err == nil {
		t.Fatal("expected error from CompositeSink")
	}
	// Both non-failing sinks must still be called.
	if s1.Count() != 1 || s3.Count() != 1 {
		t.Fatalf("counts = (%d, %d), want (1, 1)", s1.Count(), s3.Count())
	}
}

func TestCompositeSink_ErrorAggregation(t *testing.T) {
	err1 := fmt.Errorf("first")
	err2 := fmt.Errorf("second")
	comp := NewCompositeSink(
		&failingSink{err: err1},
		&failingSink{err: err2},
	)

	e := NewEvent()
	err := comp.Emit(context.Background(), &e)
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	// errors.Join produces an error that Unwrap()s to both.
	if !errors.Is(err, err1) {
		t.Fatalf("aggregated error does not contain err1")
	}
	if !errors.Is(err, err2) {
		t.Fatalf("aggregated error does not contain err2")
	}
}

func TestCompositeSink_Sinks(t *testing.T) {
	s1 := &countingSink{}
	s2 := &countingSink{}
	comp := NewCompositeSink(s1, s2)
	sinks := comp.Sinks()
	if len(sinks) != 2 {
		t.Fatalf("Sinks() len = %d, want 2", len(sinks))
	}
}

func TestCompositeSink_PanicsOnEmpty(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for empty sinks")
		}
	}()
	NewCompositeSink()
}

func TestCompositeSink_DeepCopiesEvaluatedRecords(t *testing.T) {
	first := &mutatingSink{
		mutate: func(event *Event) {
			event.HooksEvaluated[0]["status"] = "mutated"
			event.RulesEvaluated[0]["details"].(map[string]any)["value"] = "changed"
		},
	}
	second := &captureSink{}
	comp := NewCompositeSink(first, second)

	event := NewEvent()
	event.HooksEvaluated = []map[string]any{{"status": "original"}}
	event.RulesEvaluated = []map[string]any{{
		"details": map[string]any{"value": "kept"},
	}}

	if err := comp.Emit(context.Background(), &event); err != nil {
		t.Fatalf("Emit error: %v", err)
	}
	if got := second.last.HooksEvaluated[0]["status"]; got != "original" {
		t.Fatalf("HooksEvaluated leaked mutation: got %v, want original", got)
	}
	details := second.last.RulesEvaluated[0]["details"].(map[string]any)
	if got := details["value"]; got != "kept" {
		t.Fatalf("RulesEvaluated leaked mutation: got %v, want kept", got)
	}
}

func TestCompositeSink_DeepCopiesPrincipal(t *testing.T) {
	first := &mutatingSink{
		mutate: func(event *Event) {
			event.Principal.(map[string]any)["user_id"] = "mutated"
		},
	}
	second := &captureSink{}
	comp := NewCompositeSink(first, second)

	event := NewEvent()
	event.Principal = map[string]any{"user_id": "original"}

	if err := comp.Emit(context.Background(), &event); err != nil {
		t.Fatalf("Emit error: %v", err)
	}
	if got := second.last.Principal.(map[string]any)["user_id"]; got != "original" {
		t.Fatalf("Principal leaked mutation: got %v, want original", got)
	}
}

// --- CollectingSink ---

func TestCollectingSink_BasicEmit(t *testing.T) {
	sink := NewCollectingSink(100)
	e := NewEvent()
	e.ToolName = "Bash"
	e.Action = ActionCallAllowed

	if err := sink.Emit(context.Background(), &e); err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}
	if events[0].ToolName != "Bash" {
		t.Fatalf("ToolName = %q, want %q", events[0].ToolName, "Bash")
	}
}

func TestCollectingSink_RingBuffer(t *testing.T) {
	sink := NewCollectingSink(3)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		e := NewEvent()
		e.CallIndex = i
		if err := sink.Emit(ctx, &e); err != nil {
			t.Fatalf("Emit error at %d: %v", i, err)
		}
	}

	events := sink.Events()
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}
	// Oldest 2 evicted; should have indices 2, 3, 4.
	if events[0].CallIndex != 2 {
		t.Fatalf("events[0].CallIndex = %d, want 2", events[0].CallIndex)
	}
	if events[2].CallIndex != 4 {
		t.Fatalf("events[2].CallIndex = %d, want 4", events[2].CallIndex)
	}
}

func TestCollectingSink_MarkAndSinceMark(t *testing.T) {
	sink := NewCollectingSink(100)
	ctx := context.Background()

	// Emit 2 events, then mark.
	for i := 0; i < 2; i++ {
		e := NewEvent()
		e.CallIndex = i
		_ = sink.Emit(ctx, &e)
	}
	m := sink.Mark()

	// Emit 3 more after mark.
	for i := 2; i < 5; i++ {
		e := NewEvent()
		e.CallIndex = i
		_ = sink.Emit(ctx, &e)
	}

	since, err := sink.SinceMark(m)
	if err != nil {
		t.Fatalf("SinceMark error: %v", err)
	}
	if len(since) != 3 {
		t.Fatalf("SinceMark len = %d, want 3", len(since))
	}
	if since[0].CallIndex != 2 {
		t.Fatalf("since[0].CallIndex = %d, want 2", since[0].CallIndex)
	}
}

func TestCollectingSink_MarkEvicted(t *testing.T) {
	sink := NewCollectingSink(3)
	ctx := context.Background()

	m := sink.Mark() // mark at 0

	// Emit 5 events -- first 2 will be evicted from buffer of size 3.
	for i := 0; i < 5; i++ {
		e := NewEvent()
		e.CallIndex = i
		_ = sink.Emit(ctx, &e)
	}

	_, err := sink.SinceMark(m)
	if err == nil {
		t.Fatal("expected MarkEvictedError")
	}
	var mee *MarkEvictedError
	if !errors.As(err, &mee) {
		t.Fatalf("error type = %T, want *MarkEvictedError", err)
	}
}

func TestCollectingSink_MarkAheadError(t *testing.T) {
	sink := NewCollectingSink(10)
	_, err := sink.SinceMark(999)
	if err == nil {
		t.Fatal("expected error for mark ahead of total")
	}
}

func TestCollectingSink_Last(t *testing.T) {
	sink := NewCollectingSink(10)
	ctx := context.Background()

	_, err := sink.Last()
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}

	e := NewEvent()
	e.ToolName = "Read"
	_ = sink.Emit(ctx, &e)

	last, err := sink.Last()
	if err != nil {
		t.Fatalf("Last error: %v", err)
	}
	if last.ToolName != "Read" {
		t.Fatalf("Last().ToolName = %q, want %q", last.ToolName, "Read")
	}
}

func TestCollectingSink_Filter(t *testing.T) {
	sink := NewCollectingSink(100)
	ctx := context.Background()

	actions := []Action{ActionCallAllowed, ActionCallDenied, ActionCallAllowed}
	for _, a := range actions {
		e := NewEvent()
		e.Action = a
		_ = sink.Emit(ctx, &e)
	}

	allowed := sink.Filter(ActionCallAllowed)
	if len(allowed) != 2 {
		t.Fatalf("Filter(ALLOWED) len = %d, want 2", len(allowed))
	}
	denied := sink.Filter(ActionCallDenied)
	if len(denied) != 1 {
		t.Fatalf("Filter(DENIED) len = %d, want 1", len(denied))
	}
}

func TestCollectingSink_Clear(t *testing.T) {
	sink := NewCollectingSink(100)
	ctx := context.Background()

	// Mark BEFORE emitting, so that after clear the mark references
	// events that are gone.
	m := sink.Mark()

	e := NewEvent()
	_ = sink.Emit(ctx, &e)

	sink.Clear()

	events := sink.Events()
	if len(events) != 0 {
		t.Fatalf("Events len after Clear = %d, want 0", len(events))
	}

	// Marks taken before clear should raise MarkEvictedError since
	// the referenced events are gone.
	_, err := sink.SinceMark(m)
	if err == nil {
		t.Fatal("expected MarkEvictedError after Clear")
	}
	var mee *MarkEvictedError
	if !errors.As(err, &mee) {
		t.Fatalf("error type = %T, want *MarkEvictedError", err)
	}
}

func TestCollectingSink_ClearPreservesCounter(t *testing.T) {
	sink := NewCollectingSink(100)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		e := NewEvent()
		_ = sink.Emit(ctx, &e)
	}

	sink.Clear()

	// Mark after clear should work.
	m := sink.Mark()

	e := NewEvent()
	e.ToolName = "AfterClear"
	_ = sink.Emit(ctx, &e)

	since, err := sink.SinceMark(m)
	if err != nil {
		t.Fatalf("SinceMark after Clear error: %v", err)
	}
	if len(since) != 1 {
		t.Fatalf("SinceMark after Clear len = %d, want 1", len(since))
	}
	if since[0].ToolName != "AfterClear" {
		t.Fatalf("ToolName = %q, want %q", since[0].ToolName, "AfterClear")
	}
}

func TestCollectingSink_PanicsOnInvalidCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for maxEvents < 1")
		}
	}()
	NewCollectingSink(0)
}

func TestCollectingSink_DeepCopiesEvent(t *testing.T) {
	sink := NewCollectingSink(10)
	ctx := context.Background()

	e := NewEvent()
	e.ToolArgs = map[string]any{"key": "original"}
	_ = sink.Emit(ctx, &e)

	// Mutate the original after emit.
	e.ToolArgs["key"] = "mutated"
	e.ToolName = "mutated"

	events := sink.Events()
	if events[0].ToolArgs["key"] != "original" {
		t.Fatalf("event was not deep-copied: ToolArgs[key] = %v", events[0].ToolArgs["key"])
	}
}

// --- Concurrency ---

func TestCollectingSink_ConcurrentEmit(t *testing.T) {
	sink := NewCollectingSink(1000)
	ctx := context.Background()
	var wg sync.WaitGroup
	n := 100

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			e := NewEvent()
			e.CallIndex = idx
			_ = sink.Emit(ctx, &e)
		}(i)
	}
	wg.Wait()

	events := sink.Events()
	if len(events) != n {
		t.Fatalf("concurrent emit: len = %d, want %d", len(events), n)
	}
}
