package session

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

// MemoryBackend is an in-memory StorageBackend implementation.
// Thread-safe via sync.RWMutex. State is lost on restart.
type MemoryBackend struct {
	mu       sync.RWMutex
	data     map[string]string
	counters map[string]int
}

// NewMemoryBackend creates a new in-memory storage backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		data:     make(map[string]string),
		counters: make(map[string]int),
	}
}

// Get returns the value for the given key, or "" if not found.
func (m *MemoryBackend) Get(_ context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check counters first
	if v, ok := m.counters[key]; ok {
		return strconv.Itoa(v), nil
	}
	return m.data[key], nil
}

// Set stores a value for the given key.
func (m *MemoryBackend) Set(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	// If setting a counter key to a number, update the counter map
	if v, err := strconv.Atoi(value); err == nil {
		m.counters[key] = v
	}
	return nil
}

// Delete removes the value for the given key.
func (m *MemoryBackend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	delete(m.counters, key)
	return nil
}

// Increment atomically increments a counter and returns the new value.
func (m *MemoryBackend) Increment(_ context.Context, key string, amount int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key] += amount
	return m.counters[key], nil
}

// BatchGet returns values for multiple keys in a single call.
func (m *MemoryBackend) BatchGet(_ context.Context, keys []string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if v, ok := m.counters[key]; ok {
			result[key] = fmt.Sprintf("%d", v)
		} else if v, ok := m.data[key]; ok {
			result[key] = v
		}
	}
	return result, nil
}
