package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ---------------------------------------------------------------------------
// Gate config types
// ---------------------------------------------------------------------------

type gateConfig struct {
	ServerURL     string   `json:"server_url"`
	APIKey        string   `json:"api_key"`
	ContractsPath string   `json:"contracts_path"`
	AuditPath     string   `json:"audit_path"`
	Installed     []string `json:"installed_assistants"`
}

// ---------------------------------------------------------------------------
// Gate directory and config I/O
// ---------------------------------------------------------------------------

func gateDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".edictum"), nil
}

func loadGateConfigDefault() (*gateConfig, error) {
	gateDir, err := gateDirectory()
	if err != nil {
		return nil, err
	}
	return loadGateConfig(filepath.Join(gateDir, "config.json"))
}

func loadGateConfig(path string) (*gateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg gateConfig
	if jErr := json.Unmarshal(data, &cfg); jErr != nil {
		return nil, fmt.Errorf("parse config: %w", jErr)
	}
	return &cfg, nil
}

func writeGateConfig(path string, cfg *gateConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWrite(path, data)
}

func updateInstalledAssistants(assistant string, add bool) error {
	gateDir, err := gateDirectory()
	if err != nil {
		return err
	}
	configPath := filepath.Join(gateDir, "config.json")
	cfg, err := loadGateConfig(configPath)
	if err != nil {
		return err
	}

	if add {
		// Avoid duplicates.
		for _, a := range cfg.Installed {
			if a == assistant {
				return writeGateConfig(configPath, cfg)
			}
		}
		cfg.Installed = append(cfg.Installed, assistant)
	} else {
		filtered := make([]string, 0, len(cfg.Installed))
		for _, a := range cfg.Installed {
			if a != assistant {
				filtered = append(filtered, a)
			}
		}
		cfg.Installed = filtered
	}
	return writeGateConfig(configPath, cfg)
}

// ---------------------------------------------------------------------------
// File utilities
// ---------------------------------------------------------------------------

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return mkErr
	}
	// Use a unique temp file to prevent concurrent write corruption.
	tmp, err := os.CreateTemp(dir, ".edictum-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, wErr := tmp.Write(data); wErr != nil {
		tmp.Close()
		os.Remove(tmpName)
		return wErr
	}
	if cErr := tmp.Close(); cErr != nil {
		os.Remove(tmpName)
		return cErr
	}
	// os.CreateTemp already creates with 0o600 (owner-only). No chmod needed.
	return os.Rename(tmpName, path)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicWrite(dst, data)
}

// ---------------------------------------------------------------------------
// WAL (write-ahead log) operations
// ---------------------------------------------------------------------------

type walEvent struct {
	Timestamp string `json:"timestamp"`
	ToolName  string `json:"tool_name"`
	Verdict   string `json:"verdict"`
	Assistant string `json:"assistant,omitempty"`
	User      string `json:"user,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func walFilePath(auditDir string) string {
	return filepath.Join(auditDir, fmt.Sprintf("wal-%s.jsonl", time.Now().UTC().Format("20060102")))
}

func appendWALEvent(auditDir string, event walEvent) error {
	if auditDir == "" {
		return nil
	}
	if mkErr := os.MkdirAll(auditDir, 0o755); mkErr != nil {
		return mkErr
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(walFilePath(auditDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func readWALEvents(auditDir string, limit int, toolFilter, verdictFilter string) ([]walEvent, error) {
	if auditDir == "" {
		return nil, nil
	}
	files, err := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var all []walEvent
	for _, f := range files {
		events, rErr := readJSONLFile(f)
		if rErr != nil {
			continue // skip corrupt files
		}
		all = append(all, events...)
	}

	// Apply filters.
	var filtered []walEvent
	for _, e := range all {
		if toolFilter != "" && e.ToolName != toolFilter {
			continue
		}
		if verdictFilter != "" && e.Verdict != verdictFilter {
			continue
		}
		filtered = append(filtered, e)
	}

	// Return last N events.
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered, nil
}

func readJSONLFile(path string) ([]walEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []walEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MB buffer, matching replay.go
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e walEvent
		if jErr := json.Unmarshal(line, &e); jErr != nil {
			continue // skip malformed lines
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}

func countWALEvents(auditDir string) int {
	if auditDir == "" {
		return 0
	}
	files, _ := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	count := 0
	for _, f := range files {
		events, err := readJSONLFile(f)
		if err == nil {
			count += len(events)
		}
	}
	return count
}

// walFileList returns the current WAL file paths in the audit directory.
// Call before reading events to snapshot which files exist.
func walFileList(auditDir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(auditDir, "wal-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// archiveWALFiles removes only the specified WAL files, avoiding a
// TOCTOU race where events written between read and delete are lost.
func archiveWALFiles(files []string) error {
	for _, f := range files {
		if rmErr := os.Remove(f); rmErr != nil {
			return rmErr
		}
	}
	return nil
}
