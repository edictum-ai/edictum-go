package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newGateInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "install <assistant>",
		Short:     "Register the gate hook with a coding assistant",
		Args:      cobra.ExactArgs(1),
		ValidArgs: supportedAssistants(),
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := installAssistant(args[0])
			if err != nil {
				return err
			}
			if updErr := updateInstalledAssistants(args[0], true); updErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: config update failed: %s\n", updErr)
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
}

func newGateUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "uninstall <assistant>",
		Short:     "Remove the gate hook from a coding assistant",
		Args:      cobra.ExactArgs(1),
		ValidArgs: supportedAssistants(),
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := uninstallAssistant(args[0])
			if err != nil {
				return err
			}
			if updErr := updateInstalledAssistants(args[0], false); updErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: config update failed: %s\n", updErr)
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
}

func newGateStatusCmd() *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current gate configuration and health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateStatus(cmd, jsonFlag)
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	return cmd
}

func runGateStatus(cmd *cobra.Command, jsonFlag bool) error {
	cfg, err := loadGateConfigDefault()
	if err != nil {
		return fmt.Errorf("no gate config found — run 'edictum gate init' first: %w", err)
	}

	files, _ := filepath.Glob(filepath.Join(cfg.ContractsPath, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(cfg.ContractsPath, "*.yml"))
	files = append(files, ymlFiles...)

	pending := countWALEvents(cfg.AuditPath)

	installed := cfg.Installed
	if len(installed) == 0 {
		installed = detectInstalledAssistants()
	}

	if jsonFlag {
		contractNames := make([]string, 0, len(files))
		for _, f := range files {
			contractNames = append(contractNames, filepath.Base(f))
		}
		if installed == nil {
			installed = []string{}
		}
		out := map[string]any{
			"contracts":      contractNames,
			"server_url":     cfg.ServerURL,
			"pending_events": pending,
			"installed":      installed,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		return enc.Encode(out)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Edictum Gate Status")
	fmt.Fprintln(w)

	if len(files) > 0 {
		for _, f := range files {
			hash := fileHash(f)
			fmt.Fprintf(w, "  Contracts: %s (sha256: %s)\n", filepath.Base(f), hash)
		}
	} else {
		fmt.Fprintln(w, "  Contracts: none")
	}

	if cfg.ServerURL != "" {
		fmt.Fprintf(w, "  Server:    %s\n", cfg.ServerURL)
	} else {
		fmt.Fprintln(w, "  Server:    not configured")
	}

	fmt.Fprintf(w, "  Audit:     %d events pending\n", pending)

	if len(installed) > 0 {
		fmt.Fprintf(w, "  Installed: %s\n", strings.Join(installed, ", "))
	} else {
		fmt.Fprintln(w, "  Installed: none")
	}

	return nil
}

func newGateAuditCmd() *cobra.Command {
	var (
		limit    int
		tool     string
		verdict  string
		jsonFlag bool
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent audit events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateAudit(cmd, limit, tool, verdict, jsonFlag)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "number of recent events")
	cmd.Flags().StringVar(&tool, "tool", "", "filter by tool name")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by verdict (allow, deny)")
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	return cmd
}

func runGateAudit(cmd *cobra.Command, limit int, tool, verdict string, jsonFlag bool) error {
	cfg, err := loadGateConfigDefault()
	if err != nil {
		return fmt.Errorf("no gate config: %w", err)
	}

	events, rErr := readWALEvents(cfg.AuditPath, limit, tool, verdict)
	if rErr != nil {
		return fmt.Errorf("reading audit events: %w", rErr)
	}

	if jsonFlag {
		if events == nil {
			events = []walEvent{}
		}
		out := map[string]any{"events": events}
		enc := json.NewEncoder(cmd.OutOrStdout())
		return enc.Encode(out)
	}

	w := cmd.OutOrStdout()
	if len(events) == 0 {
		fmt.Fprintln(w, "No audit events found.")
		return nil
	}

	fmt.Fprintf(w, "%-20s %-10s %-8s %-15s %s\n", "Time", "User", "Verdict", "Tool", "Detail")
	for _, e := range events {
		ts := e.Timestamp
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Fprintf(w, "%-20s %-10s %-8s %-15s %s\n",
			ts, e.User, strings.ToUpper(e.Verdict), e.ToolName, e.Detail)
	}
	return nil
}

func newGateSyncCmd() *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Flush buffered audit events to Console",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateSync(cmd, jsonFlag)
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	return cmd
}

func runGateSync(cmd *cobra.Command, jsonFlag bool) error {
	cfg, err := loadGateConfigDefault()
	if err != nil {
		return fmt.Errorf("no gate config: %w", err)
	}
	if cfg.ServerURL == "" {
		if jsonFlag {
			out := map[string]any{"synced": 0, "success": false, "error": "Console not configured"}
			enc := json.NewEncoder(cmd.OutOrStdout())
			_ = enc.Encode(out)
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "Console not configured. Run 'edictum gate init --server <url>'")
		}
		return &exitError{code: 1}
	}

	// Snapshot WAL files before reading to avoid TOCTOU race.
	walFiles, lErr := walFileList(cfg.AuditPath)
	if lErr != nil {
		return fmt.Errorf("listing WAL files: %w", lErr)
	}

	events, rErr := readWALEvents(cfg.AuditPath, 0, "", "")
	if rErr != nil {
		return fmt.Errorf("reading WAL: %w", rErr)
	}

	if len(events) == 0 {
		if jsonFlag {
			out := map[string]any{"synced": 0, "success": true}
			enc := json.NewEncoder(cmd.OutOrStdout())
			return enc.Encode(out)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "No events to sync.")
		return nil
	}

	payload, jErr := json.Marshal(events)
	if jErr != nil {
		return fmt.Errorf("marshaling events: %w", jErr)
	}

	url := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/audit/ingest"
	if pErr := postJSON(url, cfg.APIKey, payload); pErr != nil {
		return fmt.Errorf("sync failed: %w", pErr)
	}

	// Only delete the files that were snapshotted.
	if aErr := archiveWALFiles(walFiles); aErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: archiving WAL files: %s\n", aErr)
	}

	if jsonFlag {
		out := map[string]any{"synced": len(events), "success": true}
		enc := json.NewEncoder(cmd.OutOrStdout())
		return enc.Encode(out)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Synced %d events to Console.\n", len(events))
	return nil
}

func fileHash(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // Path is from glob, not user input.
	if err != nil {
		return "error"
	}
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
