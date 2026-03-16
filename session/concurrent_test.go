package session

import (
	"sync"
	"testing"
)

// --- 5.11: 200 concurrent ops atomic ---

func TestParity_5_11_ConcurrentOpsAtomic(t *testing.T) {
	s := newTestSession(t)
	const goroutines = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.IncrementAttempts(ctx()); err != nil {
				t.Errorf("IncrementAttempts: %v", err)
			}
		}()
	}
	wg.Wait()

	count, err := s.AttemptCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if count != goroutines {
		t.Errorf("attempt count = %d, want %d", count, goroutines)
	}
}

func TestParity_5_11_ConcurrentRecordExecution(t *testing.T) {
	s := newTestSession(t)
	const goroutines = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			success := idx%2 == 0
			if err := s.RecordExecution(ctx(), "Bash", success); err != nil {
				t.Errorf("RecordExecution: %v", err)
			}
		}(i)
	}
	wg.Wait()

	total, err := s.ExecutionCount(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if total != goroutines {
		t.Errorf("total execution count = %d, want %d", total, goroutines)
	}

	toolCount, err := s.ToolExecutionCount(ctx(), "Bash")
	if err != nil {
		t.Fatal(err)
	}
	if toolCount != goroutines {
		t.Errorf("tool execution count = %d, want %d", toolCount, goroutines)
	}
}
