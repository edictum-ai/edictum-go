package session

import (
	"context"
	"testing"
)

func ctx() context.Context { return context.Background() }

func newTestSession(t *testing.T) *Session {
	t.Helper()
	s, err := New("test-sess", NewMemoryBackend())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- 5.1: Attempt counter increment and read ---

func TestParity_5_1_AttemptCounter(t *testing.T) {
	s := newTestSession(t)

	// Starts at zero
	count, err := s.AttemptCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("initial attempt count = %d, want 0", count)
	}

	// Increment
	n, err := s.IncrementAttempts(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("first increment = %d, want 1", n)
	}

	n, err = s.IncrementAttempts(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("second increment = %d, want 2", n)
	}

	// Read back
	count, err = s.AttemptCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("attempt count after 2 increments = %d, want 2", count)
	}
}

// --- 5.2: Execution counter ---

func TestParity_5_2_ExecutionCounter(t *testing.T) {
	s := newTestSession(t)

	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}

	count, err := s.ExecutionCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("execution count = %d, want 1", count)
	}
}

// --- 5.3: Per-tool counter ---

func TestParity_5_3_PerToolCounter(t *testing.T) {
	s := newTestSession(t)

	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Read", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}

	bashCount, err := s.ToolExecutionCount(ctx(), "Bash")
	if err != nil {
		t.Fatal(err)
	}
	if bashCount != 2 {
		t.Errorf("Bash count = %d, want 2", bashCount)
	}

	readCount, err := s.ToolExecutionCount(ctx(), "Read")
	if err != nil {
		t.Fatal(err)
	}
	if readCount != 1 {
		t.Errorf("Read count = %d, want 1", readCount)
	}

	total, err := s.ExecutionCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total executions = %d, want 3", total)
	}
}

// --- 5.4: Consecutive failure increment ---

func TestParity_5_4_ConsecutiveFailureIncrement(t *testing.T) {
	s := newTestSession(t)

	if err := s.RecordExecution(ctx(), "Bash", false); err != nil {
		t.Fatal(err)
	}
	f, err := s.ConsecutiveFailures(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if f != 1 {
		t.Errorf("consecutive failures = %d, want 1", f)
	}

	if err := s.RecordExecution(ctx(), "Bash", false); err != nil {
		t.Fatal(err)
	}
	f, err = s.ConsecutiveFailures(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if f != 2 {
		t.Errorf("consecutive failures = %d, want 2", f)
	}
}

// --- 5.5: Consecutive failure reset on success ---

func TestParity_5_5_ConsecutiveFailureResetOnSuccess(t *testing.T) {
	s := newTestSession(t)

	if err := s.RecordExecution(ctx(), "Bash", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", false); err != nil {
		t.Fatal(err)
	}
	f, err := s.ConsecutiveFailures(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if f != 2 {
		t.Errorf("consecutive failures before reset = %d, want 2", f)
	}

	// Success resets the counter
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}
	f, err = s.ConsecutiveFailures(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if f != 0 {
		t.Errorf("consecutive failures after success = %d, want 0", f)
	}

	// Fail again after reset -> must be 1, not stale 0
	if err := s.RecordExecution(ctx(), "Bash", false); err != nil {
		t.Fatal(err)
	}
	f, err = s.ConsecutiveFailures(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if f != 1 {
		t.Errorf("consecutive failures after reset+fail = %d, want 1", f)
	}
}

// --- 5.6: Batch counter fetch ---

func TestParity_5_6_BatchCounterFetch(t *testing.T) {
	s := newTestSession(t)

	if _, err := s.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}

	counters, err := s.BatchGetCounters(ctx(), "Bash")
	if err != nil {
		t.Fatal(err)
	}

	if counters["attempts"] != 2 {
		t.Errorf("attempts = %d, want 2", counters["attempts"])
	}
	if counters["execs"] != 3 {
		t.Errorf("execs = %d, want 3", counters["execs"])
	}
	if counters["tool:Bash"] != 3 {
		t.Errorf("tool:Bash = %d, want 3", counters["tool:Bash"])
	}
}

func TestParity_5_6_BatchCounterWithoutTool(t *testing.T) {
	s := newTestSession(t)

	if _, err := s.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}

	counters, err := s.BatchGetCounters(ctx(), "")
	if err != nil {
		t.Fatal(err)
	}
	if counters["attempts"] != 1 {
		t.Errorf("attempts = %d, want 1", counters["attempts"])
	}
	if counters["execs"] != 0 {
		t.Errorf("execs = %d, want 0", counters["execs"])
	}
	if _, ok := counters["tool:"]; ok {
		t.Error("should not have tool key when includeTool is empty")
	}
}

// --- 5.7: StorageBackend CRUD (MemoryBackend) ---

func TestParity_5_7_MemoryBackendCRUD(t *testing.T) {
	b := NewMemoryBackend()

	// Set and Get
	if err := b.Set(ctx(), "key1", "value1"); err != nil {
		t.Fatal(err)
	}
	v, err := b.Get(ctx(), "key1")
	if err != nil {
		t.Fatal(err)
	}
	if v != "value1" {
		t.Errorf("Get = %q, want %q", v, "value1")
	}

	// Missing key returns empty string
	v, err = b.Get(ctx(), "missing")
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("missing key Get = %q, want empty", v)
	}

	// Delete
	if err := b.Delete(ctx(), "key1"); err != nil {
		t.Fatal(err)
	}
	v, err = b.Get(ctx(), "key1")
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("after delete Get = %q, want empty", v)
	}

	// Increment
	n, err := b.Increment(ctx(), "counter", 1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("first increment = %d, want 1", n)
	}
	n, err = b.Increment(ctx(), "counter", 5)
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("second increment = %d, want 6", n)
	}
}

// --- 5.8: Increment atomicity ---

func TestParity_5_8_IncrementAtomicity(t *testing.T) {
	b := NewMemoryBackend()

	// Incrementing the same key many times must produce correct totals.
	const iterations = 100
	for i := 0; i < iterations; i++ {
		n, err := b.Increment(ctx(), "counter", 1)
		if err != nil {
			t.Fatal(err)
		}
		if n != i+1 {
			t.Errorf("iteration %d: got %d, want %d", i, n, i+1)
		}
	}
}

// --- 5.9: BatchGet interface ---

func TestParity_5_9_BatchGetInterface(t *testing.T) {
	b := NewMemoryBackend()

	// MemoryBackend implements BatchGetter
	var bg BatchGetter = b
	_ = bg

	if err := b.Set(ctx(), "a", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Increment(ctx(), "b", 42); err != nil {
		t.Fatal(err)
	}

	result, err := b.BatchGet(ctx(), []string{"a", "b", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if result["a"] != "1" {
		t.Errorf("a = %q, want %q", result["a"], "1")
	}
	if result["b"] != "42" {
		t.Errorf("b = %q, want %q", result["b"], "42")
	}
	if v, ok := result["missing"]; ok && v != "" {
		t.Errorf("missing = %q, want empty or absent", v)
	}
}

// --- 5.10: Session isolation ---

func TestParity_5_10_SessionIsolation(t *testing.T) {
	backend := NewMemoryBackend()

	s1, err := New("session-1", backend)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := New("session-2", backend)
	if err != nil {
		t.Fatal(err)
	}

	// Increment session 1
	if _, err := s1.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}
	if err := s1.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}

	// Session 2 should be unaffected
	c, err := s2.AttemptCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if c != 0 {
		t.Errorf("session-2 attempts = %d, want 0", c)
	}

	e, err := s2.ExecutionCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if e != 0 {
		t.Errorf("session-2 execs = %d, want 0", e)
	}

	// Session IDs
	if s1.ID() != "session-1" {
		t.Errorf("s1.ID() = %q, want %q", s1.ID(), "session-1")
	}
	if s2.ID() != "session-2" {
		t.Errorf("s2.ID() = %q, want %q", s2.ID(), "session-2")
	}
}

// --- Session ID validation ---

func TestSession_IDValidation(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"null byte", "sess\x00id"},
		{"newline", "sess\nid"},
		{"path separator", "sess/id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.id, NewMemoryBackend())
			if err == nil {
				t.Fatalf("expected error for session ID %q, got nil", tc.id)
			}
		})
	}
}

// --- Key scheme verification ---

func TestParity_KeyScheme(t *testing.T) {
	b := NewMemoryBackend()
	s, err := New("test-sess", b)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.IncrementAttempts(ctx()); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExecution(ctx(), "Bash", true); err != nil {
		t.Fatal(err)
	}

	// Verify internal key scheme by reading from backend directly
	v, err := b.Get(ctx(), "s:test-sess:attempts")
	if err != nil {
		t.Fatal(err)
	}
	if v != "1" {
		t.Errorf("attempts key value = %q, want %q", v, "1")
	}

	v, err = b.Get(ctx(), "s:test-sess:execs")
	if err != nil {
		t.Fatal(err)
	}
	if v != "1" {
		t.Errorf("execs key value = %q, want %q", v, "1")
	}

	v, err = b.Get(ctx(), "s:test-sess:tool:Bash")
	if err != nil {
		t.Fatal(err)
	}
	if v != "1" {
		t.Errorf("tool:Bash key value = %q, want %q", v, "1")
	}
}
