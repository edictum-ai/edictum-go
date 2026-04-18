package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/edictum-ai/edictum-go/workflow"
	"github.com/spf13/cobra"
)

type gateWorkflowStatus struct {
	SessionID       string
	SessionSource   string
	WorkflowName    string
	CurrentStage    string
	ProgressCurrent int
	ProgressTotal   int
	CompletedStages []string
	NextStage       string
	Resolved        bool
	StateExists     bool
	ResolutionError string
	Hint            string
}

const gateWorkflowResolutionHint = "run from a git worktree, create .edictum-session, or pass --session-id"

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
	var (
		jsonFlag  bool
		sessionID string
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current gate configuration and health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateStatus(cmd, jsonFlag, sessionID)
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "inspect a specific workflow session")
	return cmd
}

func runGateStatus(cmd *cobra.Command, jsonFlag bool, explicitSessionID string) error {
	cfg, err := loadGateConfigDefault()
	if err != nil {
		return fmt.Errorf("no gate config found — run 'edictum gate init' first: %w", err)
	}

	files, _ := filepath.Glob(filepath.Join(cfg.RulesPath, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(cfg.RulesPath, "*.yml"))
	files = append(files, ymlFiles...)

	pending := countWALEvents(cfg.AuditPath)

	installed := cfg.Installed
	if len(installed) == 0 {
		installed = detectInstalledAssistants()
	}

	if jsonFlag {
		ruleNames := make([]string, 0, len(files))
		for _, f := range files {
			ruleNames = append(ruleNames, filepath.Base(f))
		}
		if installed == nil {
			installed = []string{}
		}
		workflowName := ""
		var workflowStatus *gateWorkflowStatus
		if cfg.WorkflowPath != "" {
			ctx, err := loadGateWorkflowContext("", cfg.WorkflowExecEnabled, true)
			if err != nil {
				return err
			}
			workflowName = ctx.workflowName
			workflowStatus, err = resolveGateWorkflowStatus(ctx, explicitSessionID)
			if err != nil {
				return err
			}
		}
		out := map[string]any{
			"rules":                 ruleNames,
			"environment":           cfg.Environment,
			"workflow":              workflowName,
			"workflow_exec_enabled": cfg.WorkflowExecEnabled,
			"server_url":            cfg.ServerURL,
			"pending_events":        pending,
			"installed":             installed,
		}
		if workflowStatus != nil {
			out["workflow_session_resolved"] = workflowStatus.Resolved
			out["workflow_state_exists"] = workflowStatus.StateExists
			if workflowStatus.Resolved {
				out["workflow_session_id"] = workflowStatus.SessionID
				out["workflow_session_source"] = workflowStatus.SessionSource
			}
			if workflowStatus.Resolved && workflowStatus.StateExists {
				out["workflow_current_stage"] = workflowStatus.CurrentStage
				out["workflow_progress"] = map[string]int{
					"current": workflowStatus.ProgressCurrent,
					"total":   workflowStatus.ProgressTotal,
				}
				out["workflow_completed_stages"] = workflowStatus.CompletedStages
				if workflowStatus.NextStage != "" {
					out["workflow_next_stage"] = workflowStatus.NextStage
				}
			}
			if !workflowStatus.Resolved {
				out["workflow_resolution_error"] = workflowStatus.ResolutionError
				out["workflow_resolution_hint"] = workflowStatus.Hint
			}
			if workflowStatus.Resolved && !workflowStatus.StateExists {
				out["workflow_state"] = "not_started"
			}
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
			fmt.Fprintf(w, "  Rules:     %s (sha256: %s)\n", filepath.Base(f), hash)
		}
	} else {
		fmt.Fprintln(w, "  Rules:     none")
	}
	var workflowStatus *gateWorkflowStatus
	if cfg.WorkflowPath != "" {
		ctx, err := loadGateWorkflowContext("", cfg.WorkflowExecEnabled, true)
		if err != nil {
			return err
		}
		hash := fileHash(cfg.WorkflowPath)
		fmt.Fprintf(w, "  Workflow:  %s (sha256: %s)\n", ctx.workflowName, hash)
		if cfg.WorkflowExecEnabled {
			fmt.Fprintln(w, "  Workflow exec(...): enabled")
		}
		workflowStatus, err = resolveGateWorkflowStatus(ctx, explicitSessionID)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, "  Workflow:  none")
	}

	if cfg.ServerURL != "" {
		fmt.Fprintf(w, "  Server:    %s\n", cfg.ServerURL)
	} else {
		fmt.Fprintln(w, "  Server:    not configured")
	}
	fmt.Fprintf(w, "  Env:       %s\n", cfg.Environment)

	fmt.Fprintf(w, "  Decision log: %d events pending\n", pending)

	if len(installed) > 0 {
		fmt.Fprintf(w, "  Installed: %s\n", strings.Join(installed, ", "))
	} else {
		fmt.Fprintln(w, "  Installed: none")
	}
	if workflowStatus != nil {
		fmt.Fprintln(w, "  Workflow State:")
		fmt.Fprintf(w, "    Workflow: %s\n", workflowStatus.WorkflowName)
		if !workflowStatus.Resolved {
			fmt.Fprintln(w, "    Session: unresolved")
			fmt.Fprintf(w, "    Reason: %s\n", workflowStatus.ResolutionError)
			fmt.Fprintf(w, "    Hint: %s\n", workflowStatus.Hint)
			return nil
		}
		if workflowStatus.SessionSource == "flag" {
			fmt.Fprintf(w, "    Session: %s\n", workflowStatus.SessionID)
		} else {
			fmt.Fprintf(w, "    Session: %s (%s)\n", workflowStatus.SessionID, workflowStatus.SessionSource)
		}
		if !workflowStatus.StateExists {
			fmt.Fprintln(w, "    State: not started yet")
			return nil
		}
		fmt.Fprintf(w, "    Stage: %s\n", workflowStatus.CurrentStage)
		fmt.Fprintf(w, "    Progress: %d/%d\n", workflowStatus.ProgressCurrent, workflowStatus.ProgressTotal)
		if len(workflowStatus.CompletedStages) > 0 {
			fmt.Fprintf(w, "    Completed: %s\n", strings.Join(workflowStatus.CompletedStages, " -> "))
		} else {
			fmt.Fprintln(w, "    Completed: none")
		}
		if workflowStatus.NextStage != "" {
			fmt.Fprintf(w, "    Next: %s\n", workflowStatus.NextStage)
		}
	}

	return nil
}

func newGateAuditCmd() *cobra.Command {
	var (
		limit    int
		tool     string
		decision string
		jsonFlag bool
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent decision log events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateAudit(cmd, limit, tool, decision, jsonFlag)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "number of recent events")
	cmd.Flags().StringVar(&tool, "tool", "", "filter by tool name")
	cmd.Flags().StringVar(&decision, "decision", "", "filter by decision (allow, block)")
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	return cmd
}

func runGateAudit(cmd *cobra.Command, limit int, tool, decision string, jsonFlag bool) error {
	cfg, err := loadGateConfigDefault()
	if err != nil {
		return fmt.Errorf("no gate config: %w", err)
	}

	events, rErr := readWALEvents(cfg.AuditPath, limit, tool, decision)
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
		fmt.Fprintln(w, "No decision log events found.")
		return nil
	}

	fmt.Fprintf(w, "%-20s %-10s %-8s %-15s %s\n", "Time", "User", "Decision", "Tool", "Detail")
	for _, e := range events {
		ts := e.Timestamp
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Fprintf(w, "%-20s %-10s %-8s %-15s %s\n",
			ts, e.User, strings.ToUpper(e.Decision), e.ToolName, e.Reason)
	}
	return nil
}

func newGateSyncCmd() *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Flush buffered decision log events to server",
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
			out := map[string]any{"synced": 0, "success": false, "error": "server not configured"}
			enc := json.NewEncoder(cmd.OutOrStdout())
			_ = enc.Encode(out)
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "Server not configured. Run 'edictum gate init --server <url>'")
		}
		return &exitError{code: 1}
	}

	// Snapshot WAL files before reading to avoid TOCTOU race.
	walFiles, lErr := walFileList(cfg.AuditPath)
	if lErr != nil {
		return fmt.Errorf("listing WAL files: %w", lErr)
	}

	// Read only from snapshotted files to avoid uploading events written
	// concurrently and then deleting them (which would cause data loss).
	events, rErr := readWALFromFiles(walFiles)
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

	payload, jErr := json.Marshal(map[string]any{"events": events})
	if jErr != nil {
		return fmt.Errorf("marshaling events: %w", jErr)
	}

	url := strings.TrimRight(cfg.ServerURL, "/") + "/v1/events"
	if pErr := postJSON(url, cfg.APIKey, payload); pErr != nil {
		return fmt.Errorf("sync failed: %w", pErr)
	}

	// Only delete snapshotted files, excluding today's WAL (still being
	// written by concurrent gate check invocations). Today's events that
	// were uploaded will be re-uploaded on next sync — safe duplication
	// vs unsafe data loss from deleting an actively-written file.
	today := walFilePath(cfg.AuditPath)
	var toDelete []string
	for _, f := range walFiles {
		if f != today {
			toDelete = append(toDelete, f)
		}
	}
	if len(toDelete) > 0 {
		if aErr := archiveWALFiles(toDelete); aErr != nil {
			return fmt.Errorf("sync succeeded but WAL cleanup failed (events may be re-uploaded): %w", aErr)
		}
	}

	if jsonFlag {
		out := map[string]any{"synced": len(events), "success": true}
		enc := json.NewEncoder(cmd.OutOrStdout())
		return enc.Encode(out)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Synced %d events to server.\n", len(events))
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

func resolveGateWorkflowStatus(ctx *gateWorkflowRuntimeContext, explicitSessionID string) (*gateWorkflowStatus, error) {
	status := &gateWorkflowStatus{
		WorkflowName:  ctx.workflowName,
		ProgressTotal: len(ctx.runtime.Definition().Stages),
		Hint:          gateWorkflowResolutionHint,
	}

	sessionID := ""
	if resolvedSessionID, resolvedSource, resolveErr := resolveSessionID(explicitSessionID, ctx.workflowName); resolveErr != nil {
		status.ResolutionError = resolveErr.Error()
	} else {
		status.Resolved = true
		status.SessionID = resolvedSessionID
		status.SessionSource = resolvedSource
		sessionID = resolvedSessionID
	}
	if !status.Resolved {
		return status, nil
	}

	snapshot, snapshotErr := loadGateWorkflowStateSnapshot(ctx.runtime, sessionID)
	if snapshotErr != nil {
		return nil, snapshotErr
	}
	if !snapshot.Exists {
		return status, nil
	}

	status.StateExists = true
	state := snapshot.State

	progressCurrent := len(state.CompletedStages)
	currentStage := state.ActiveStage
	if currentStage == "" {
		currentStage = "completed"
		progressCurrent = len(ctx.runtime.Definition().Stages)
	} else {
		progressCurrent++
	}

	status.CurrentStage = currentStage
	status.ProgressCurrent = progressCurrent
	status.CompletedStages = append([]string{}, state.CompletedStages...)
	status.NextStage = nextWorkflowStage(ctx.runtime.Definition(), state)
	return status, nil
}

func nextWorkflowStage(def workflow.Definition, state workflow.State) string {
	if state.ActiveStage == "" {
		return ""
	}
	idx, ok := def.StageIndex(state.ActiveStage)
	if !ok {
		return ""
	}
	next := idx + 1
	if next >= len(def.Stages) {
		return ""
	}
	return def.Stages[next].ID
}
