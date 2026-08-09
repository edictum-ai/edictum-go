package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityUninstallOpenCodeRequiresGeneratedSignature(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pluginPath := filepath.Join(home, ".opencode", "plugins", "edictum-gate.ts")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o755); err != nil {
		t.Fatal(err)
	}
	userPlugin := []byte("// user-managed plugin\n")
	if err := os.WriteFile(pluginPath, userPlugin, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := uninstallOpenCode()
	if err == nil || !strings.Contains(err.Error(), "refusing to remove") {
		t.Fatalf("error = %v, want refusal for unrecognized plugin", err)
	}
	got, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(userPlugin) {
		t.Fatal("unrecognized OpenCode plugin was modified")
	}

	if err := os.WriteFile(pluginPath, []byte(opencodePluginContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := uninstallOpenCode(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("generated OpenCode plugin still exists: %v", err)
	}
}
