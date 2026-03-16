package audit

import (
	"context"
	"fmt"
	"sync"
)

// MarkEvictedError is returned when a mark references events that
// have been evicted from the ring buffer.
type MarkEvictedError struct {
	Mark       int
	BufferBase int
	MaxEvents  int
}

func (e *MarkEvictedError) Error() string {
	return fmt.Sprintf(
		"mark %d references evicted events (buffer starts at %d, max_events=%d)",
		e.Mark, e.BufferBase, e.MaxEvents,
	)
}

// CollectingSink stores events in memory with a bounded ring buffer.
// Supports mark-based windowed queries using absolute positions.
//
// Marks track absolute positions in the total event stream. If events
// referenced by a mark have been evicted due to buffer overflow,
// SinceMark returns MarkEvictedError.
type CollectingSink struct {
	mu           sync.Mutex
	events       []Event
	maxEvents    int
	totalEmitted int // monotonic counter, never resets
}

// NewCollectingSink creates a sink that collects events in memory.
// maxEvents must be >= 1.
func NewCollectingSink(maxEvents int) *CollectingSink {
	if maxEvents < 1 {
		panic(fmt.Sprintf("maxEvents must be >= 1, got %d", maxEvents))
	}
	return &CollectingSink{
		events:    make([]Event, 0, maxEvents),
		maxEvents: maxEvents,
	}
}

// Emit adds an event to the buffer. The event is deep-copied to prevent
// post-emit mutation from affecting audit integrity.
func (c *CollectingSink) Emit(_ context.Context, event *Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cp := *event
	if event.ToolArgs != nil {
		cp.ToolArgs = make(map[string]any, len(event.ToolArgs))
		for k, v := range event.ToolArgs {
			cp.ToolArgs[k] = v
		}
	}

	c.events = append(c.events, cp)
	c.totalEmitted++

	if len(c.events) > c.maxEvents {
		c.events = c.events[len(c.events)-c.maxEvents:]
	}
	return nil
}

// Events returns a defensive copy of all collected events.
func (c *CollectingSink) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Event, len(c.events))
	copy(cp, c.events)
	return cp
}

// Mark returns an absolute position marker at the current end of
// the event stream. The marker is a monotonic counter value, not
// a buffer index.
func (c *CollectingSink) Mark() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalEmitted
}

// SinceMark returns events emitted after the given mark.
// Returns MarkEvictedError if events between the mark and the
// current buffer start have been evicted.
func (c *CollectingSink) SinceMark(m int) ([]Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if m > c.totalEmitted {
		return nil, fmt.Errorf("mark %d is ahead of total emitted (%d)", m, c.totalEmitted)
	}

	evictedCount := c.totalEmitted - len(c.events)
	if m < evictedCount {
		return nil, &MarkEvictedError{
			Mark:       m,
			BufferBase: evictedCount,
			MaxEvents:  c.maxEvents,
		}
	}

	bufferOffset := m - evictedCount
	result := make([]Event, len(c.events)-bufferOffset)
	copy(result, c.events[bufferOffset:])
	return result, nil
}

// Last returns the most recent event. Returns an error if the buffer
// is empty.
func (c *CollectingSink) Last() (Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return Event{}, fmt.Errorf("no events in buffer")
	}
	return c.events[len(c.events)-1], nil
}

// Filter returns all events matching the given action.
func (c *CollectingSink) Filter(action Action) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []Event
	for _, e := range c.events {
		if e.Action == action {
			result = append(result, e)
		}
	}
	return result
}

// Clear discards all collected events. Does not reset the total
// counter. Marks taken before Clear will return MarkEvictedError
// since the referenced events are gone.
func (c *CollectingSink) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = c.events[:0]
}
