package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type gateFileBackend struct {
	path string
}

func newGateFileBackend(path string) *gateFileBackend {
	return &gateFileBackend{path: path}
}

func (b *gateFileBackend) Get(_ context.Context, key string) (string, error) {
	state, unlock, err := b.lockedState()
	if err != nil {
		return "", err
	}
	defer unlock()
	return state[key], nil
}

func (b *gateFileBackend) Set(_ context.Context, key, value string) error {
	state, unlock, err := b.lockedState()
	if err != nil {
		return err
	}
	defer unlock()
	state[key] = value
	return b.writeLocked(state)
}

func (b *gateFileBackend) Delete(_ context.Context, key string) error {
	state, unlock, err := b.lockedState()
	if err != nil {
		return err
	}
	defer unlock()
	delete(state, key)
	return b.writeLocked(state)
}

func (b *gateFileBackend) Increment(_ context.Context, key string, amount int) (int, error) {
	state, unlock, err := b.lockedState()
	if err != nil {
		return 0, err
	}
	defer unlock()

	current := 0
	if raw, ok := state[key]; ok && raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("decode counter %q: %w", key, err)
		}
		current = parsed
	}
	current += amount
	state[key] = strconv.Itoa(current)
	if err := b.writeLocked(state); err != nil {
		return 0, err
	}
	return current, nil
}

func (b *gateFileBackend) BatchGet(_ context.Context, keys []string) (map[string]string, error) {
	state, unlock, err := b.lockedState()
	if err != nil {
		return nil, err
	}
	defer unlock()

	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := state[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}

func (b *gateFileBackend) lockedState() (map[string]string, func(), error) {
	lockPath := b.path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, nil, err
	}

	lockHandle, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := lockFile(lockHandle); err != nil {
		lockHandle.Close()
		return nil, nil, err
	}

	unlock := func() {
		_ = lockHandle.Close()
	}

	raw, err := os.ReadFile(b.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, unlock, nil
		}
		unlock()
		return nil, nil, err
	}
	if len(raw) == 0 {
		return map[string]string{}, unlock, nil
	}

	var state map[string]string
	if err := json.Unmarshal(raw, &state); err != nil {
		unlock()
		return nil, nil, fmt.Errorf("decode session store: %w", err)
	}
	if state == nil {
		state = map[string]string{}
	}
	return state, unlock, nil
}

func (b *gateFileBackend) writeLocked(state map[string]string) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(b.path, data)
}
