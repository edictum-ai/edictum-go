package approval

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryBackend is an in-memory approval backend for tests and local use.
type MemoryBackend struct {
	mu        sync.Mutex
	nextID    int
	requests  map[string]Request
	decisions map[string]Decision
	waiters   map[string]chan struct{}
	requestCh chan Request
}

// NewMemoryBackend creates a new in-memory approval backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		requests:  make(map[string]Request),
		decisions: make(map[string]Decision),
		waiters:   make(map[string]chan struct{}),
		requestCh: make(chan Request, 128),
	}
}

// RequestApproval stores a pending approval request in memory.
func (b *MemoryBackend) RequestApproval(
	_ context.Context,
	toolName string,
	toolArgs map[string]any,
	message string,
	opts ...RequestOption,
) (Request, error) {
	b.mu.Lock()
	b.nextID++
	id := fmt.Sprintf("approval-%d", b.nextID)
	req := NewRequest(id, toolName, toolArgs, message, opts...)
	b.requests[id] = req
	b.waiters[id] = make(chan struct{})
	b.mu.Unlock()

	b.requestCh <- req
	return req, nil
}

// PollApprovalStatus waits for an approval decision or context cancellation.
func (b *MemoryBackend) PollApprovalStatus(ctx context.Context, approvalID string) (Decision, error) {
	b.mu.Lock()
	if decision, ok := b.decisions[approvalID]; ok {
		b.mu.Unlock()
		return decision, nil
	}
	waiter, ok := b.waiters[approvalID]
	b.mu.Unlock()
	if !ok {
		return Decision{}, fmt.Errorf("approval not found: %s", approvalID)
	}

	select {
	case <-waiter:
		b.mu.Lock()
		decision := b.decisions[approvalID]
		b.mu.Unlock()
		return decision, nil
	case <-ctx.Done():
		return Decision{
			Status:    StatusTimeout,
			Timestamp: time.Now().UTC(),
		}, ctx.Err()
	}
}

// WaitForRequest returns the next approval request created by RequestApproval.
func (b *MemoryBackend) WaitForRequest(ctx context.Context) (Request, error) {
	select {
	case req := <-b.requestCh:
		return req, nil
	case <-ctx.Done():
		return Request{}, ctx.Err()
	}
}

// Approve resolves an approval request as approved.
func (b *MemoryBackend) Approve(approvalID, approver, reason string) error {
	return b.setDecision(approvalID, Decision{
		Approved:  true,
		Approver:  approver,
		Reason:    reason,
		Status:    StatusApproved,
		Timestamp: time.Now().UTC(),
	})
}

// Deny resolves an approval request as denied.
func (b *MemoryBackend) Deny(approvalID, approver, reason string) error {
	return b.setDecision(approvalID, Decision{
		Approver:  approver,
		Reason:    reason,
		Status:    StatusDenied,
		Timestamp: time.Now().UTC(),
	})
}

func (b *MemoryBackend) setDecision(approvalID string, decision Decision) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.requests[approvalID]; !ok {
		return fmt.Errorf("approval not found: %s", approvalID)
	}
	if _, ok := b.decisions[approvalID]; ok {
		return fmt.Errorf("approval already decided: %s", approvalID)
	}

	waiter, ok := b.waiters[approvalID]
	if !ok {
		return fmt.Errorf("approval waiter missing: %s", approvalID)
	}

	b.decisions[approvalID] = decision
	close(waiter)
	delete(b.waiters, approvalID)
	return nil
}
