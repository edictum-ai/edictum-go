package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// JSON file helpers
// ---------------------------------------------------------------------------

func readJSONFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if jErr := json.Unmarshal(data, &m); jErr != nil {
		return nil, jErr
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func writeJSONFileAtomic(path string, data map[string]any) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return mkErr
	}
	return atomicWrite(path, encoded)
}

func ensureMap(m map[string]any, key string) map[string]any {
	v, ok := m[key].(map[string]any)
	if !ok || v == nil {
		v = map[string]any{}
		m[key] = v
	}
	return v
}

func ensureSlice(m map[string]any, key string) []any {
	v, ok := m[key].([]any)
	if !ok {
		v = []any{}
		m[key] = v
	}
	return v
}

// containsHookMarker checks nested hook entries (Claude Code style: entries[].hooks[].command).
func containsHookMarker(entries []any, hooksKey, cmdKey string) bool {
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			continue
		}
		hs, _ := m[hooksKey].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			cmd, _ := hm[cmdKey].(string)
			if strings.Contains(cmd, edictumHookMarker) {
				return true
			}
		}
	}
	return false
}

// containsHookMarkerDirect checks flat hook entries (Cursor/Copilot style: entries[].command).
func containsHookMarkerDirect(entries []any, cmdKey string) bool {
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			continue
		}
		cmd, _ := m[cmdKey].(string)
		if strings.Contains(cmd, edictumHookMarker) {
			return true
		}
	}
	return false
}

// filterHookEntries removes nested edictum hooks (Claude Code style).
func filterHookEntries(entries []any, hooksKey, cmdKey string) ([]any, bool) {
	var filtered []any
	removed := false
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			filtered = append(filtered, entry)
			continue
		}
		hs, _ := m[hooksKey].([]any)
		var clean []any
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				clean = append(clean, h)
				continue
			}
			cmd, _ := hm[cmdKey].(string)
			if strings.Contains(cmd, edictumHookMarker) {
				removed = true
				continue
			}
			clean = append(clean, h)
		}
		if len(clean) > 0 {
			m[hooksKey] = clean
			filtered = append(filtered, m)
		}
	}
	return filtered, removed
}

// filterDirectEntries removes flat edictum hooks (Cursor/Copilot style).
func filterDirectEntries(entries []any, cmdKey string) ([]any, bool) {
	var filtered []any
	removed := false
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		if m == nil {
			filtered = append(filtered, entry)
			continue
		}
		cmd, _ := m[cmdKey].(string)
		if strings.Contains(cmd, edictumHookMarker) {
			removed = true
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, removed
}

// ---------------------------------------------------------------------------
// HTTP and user helpers
// ---------------------------------------------------------------------------

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func postJSON(url, apiKey string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}
