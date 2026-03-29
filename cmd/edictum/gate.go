package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/spf13/cobra"
)

func newGateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Coding assistant governance via hook interception",
		Long:  "Manage Edictum Gate — governance enforcement for coding assistants (Claude Code, Cursor, Copilot, Gemini, OpenCode).",
	}

	cmd.AddCommand(
		newGateInitCmd(),
		newGateCheckCmd(),
		newGateRunCmd(),
		newGateResetCmd(),
		newGateInstallCmd(),
		newGateUninstallCmd(),
		newGateStatusCmd(),
		newGateAuditCmd(),
		newGateSyncCmd(),
	)
	return cmd
}

func newGateInitCmd() *cobra.Command {
	var (
		serverURL      string
		apiKey         string
		rulesPath      string
		environment    string
		workflowPath   string
		workflowExec   bool
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up Edictum Gate governance",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateInit(cmd, serverURL, apiKey, rulesPath, environment, workflowPath, workflowExec, nonInteractive)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Console server URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Console API key")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "custom Ruleset YAML")
	cmd.Flags().StringVar(&environment, "environment", "production", "environment name")
	cmd.Flags().StringVar(&workflowPath, "workflow", "", "custom Workflow YAML")
	cmd.Flags().BoolVar(&workflowExec, "workflow-exec", false, "enable trusted exec(...) workflow conditions")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip prompts, use defaults")
	return cmd
}

func runGateInit(cmd *cobra.Command, serverURL, apiKey, rulesPath, environment, workflowPath string, workflowExec bool, _ bool) error {
	if workflowExec && workflowPath == "" {
		return fmt.Errorf("--workflow-exec requires --workflow")
	}

	gateDir, err := gateDirectory()
	if err != nil {
		return err
	}

	dirs := []string{
		gateDir,
		filepath.Join(gateDir, "rules"),
		filepath.Join(gateDir, "workflows"),
		filepath.Join(gateDir, "state"),
		filepath.Join(gateDir, "audit"),
	}
	for _, d := range dirs {
		if mkErr := os.MkdirAll(d, 0o755); mkErr != nil {
			return fmt.Errorf("creating %s: %w", d, mkErr)
		}
	}

	cfg := &gateConfig{
		ServerURL:   serverURL,
		APIKey:      apiKey,
		RulesPath:   filepath.Join(gateDir, "rules"),
		Environment: environment,
		AuditPath:   filepath.Join(gateDir, "audit"),
	}

	if rulesPath != "" {
		copiedRules, cpErr := syncYAMLInput(rulesPath, cfg.RulesPath)
		if cpErr != nil {
			return fmt.Errorf("copying rules: %w", cpErr)
		}
		if _, buildErr := guard.FromYAML(cfg.RulesPath); buildErr != nil {
			for _, path := range copiedRules {
				_ = os.Remove(path)
			}
			return fmt.Errorf("rule validation failed: %w", buildErr)
		}
	}
	if workflowPath != "" {
		dst := filepath.Join(gateDir, "workflows", filepath.Base(workflowPath))
		if cpErr := copyFile(workflowPath, dst); cpErr != nil {
			return fmt.Errorf("copying workflow: %w", cpErr)
		}
		if _, loadErr := loadGateWorkflowRuntime(dst, workflowExec); loadErr != nil {
			_ = os.Remove(dst)
			return fmt.Errorf("workflow validation failed: %w", loadErr)
		}
		cfg.WorkflowPath = dst
		cfg.WorkflowExecEnabled = workflowExec
	}

	configPath := filepath.Join(gateDir, "config.json")
	if wErr := writeGateConfig(configPath, cfg); wErr != nil {
		return fmt.Errorf("writing config: %w", wErr)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Edictum Gate initialized.")
	fmt.Fprintf(w, "  Config:    %s\n", configPath)
	fmt.Fprintf(w, "  Rules:     %s\n", cfg.RulesPath)
	fmt.Fprintf(w, "  Env:       %s\n", cfg.Environment)
	if cfg.WorkflowPath != "" {
		fmt.Fprintf(w, "  Workflow:  %s\n", cfg.WorkflowPath)
		if cfg.WorkflowExecEnabled {
			fmt.Fprintln(w, "  Workflow exec(...): enabled")
		}
	}
	fmt.Fprintf(w, "  Audit:     %s\n", cfg.AuditPath)
	if serverURL != "" {
		fmt.Fprintf(w, "  Server:    %s\n", serverURL)
	}
	return nil
}

func newGateCheckCmd() *cobra.Command {
	var (
		format    string
		rulesPath string
		jsonFlag  bool
	)

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate a tool call from stdin against rules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateCheck(cmd, format, rulesPath, jsonFlag)
		},
	}

	cmd.Flags().StringVar(&format, "format", "claude-code", "output format (claude-code, cursor, copilot, gemini, opencode, raw)")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "override rule path")
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "force JSON output")
	return cmd
}

// maxStdinBytes is the maximum input size for gate check (10 MB).
// Prevents OOM on large tool_input payloads (e.g., Write with multi-MB files).
const maxStdinBytes = 10 * 1024 * 1024

func runGateCheck(cmd *cobra.Command, format, rulesOverride string, jsonFlag bool) error {
	if jsonFlag {
		format = "raw"
	}

	raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxStdinBytes+1))
	if err != nil {
		return gateCheckError(cmd, format, fmt.Sprintf("reading stdin: %s", err))
	}
	if len(raw) > maxStdinBytes {
		return gateCheckError(cmd, format, "stdin input exceeds 10 MB limit")
	}

	toolName, toolArgs, parseErr := parseFormatStdin(format, raw)
	if parseErr != nil {
		return gateCheckError(cmd, format, fmt.Sprintf("parsing input: %s", parseErr))
	}

	// Load config once for both rules path and audit path.
	cfg, _ := loadGateConfigDefault() // nil if no config exists — audit is optional
	cPath := rulesOverride
	if cPath == "" {
		if cfg == nil {
			return gateCheckError(cmd, format, "no gate config found — run 'edictum gate init'")
		}
		cPath = cfg.RulesPath
	}

	g, gErr := buildGuardFromPath(cPath)
	if gErr != nil {
		return gateCheckError(cmd, format, fmt.Sprintf("loading rules: %s", gErr))
	}

	ctx := context.Background()
	result := g.Evaluate(ctx, toolName, toolArgs)

	ruleID := extractRuleID(result)
	reason := ""
	if len(result.BlockReasons) > 0 {
		reason = result.BlockReasons[0]
	}

	// Append audit event with timestamp.
	if cfg != nil && cfg.AuditPath != "" {
		_ = appendWALEvent(cfg.AuditPath, walEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ToolName:  toolName,
			Decision:  result.Decision,
			User:      currentUser(),
			Reason:    reason,
		})
	}

	if result.Decision == "block" {
		return writeCheckDeny(cmd, format, buildDenyReason(ruleID, reason))
	}
	return writeCheckOutput(cmd, format, "allow", "", "")
}

func gateCheckError(cmd *cobra.Command, format, msg string) error {
	// Output a deny-formatted response to stdout so the assistant sees a
	// deny even if it ignores exit codes. Defence-in-depth: some hook
	// systems treat exit 2 as "allow".
	_ = writeCheckOutput(cmd, format, "block", "", msg)
	return &exitError{code: 2}
}

func newGateResetCmd() *cobra.Command {
	var (
		stageID      string
		sessionID    string
		workflowPath string
		workflowExec bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset the active workflow session to a named stage",
		RunE: func(cmd *cobra.Command, _ []string) error {
			workflowExecSet := cmd.Flags().Lookup("workflow-exec").Changed
			return runGateReset(cmd, stageID, sessionID, workflowPath, workflowExec, workflowExecSet)
		},
	}

	cmd.Flags().StringVar(&stageID, "stage", "", "stage ID to reset to")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "stable session ID for persisted runtime state")
	cmd.Flags().StringVar(&workflowPath, "workflow", "", "override workflow path")
	cmd.Flags().BoolVar(&workflowExec, "workflow-exec", false, "enable trusted exec(...) workflow conditions")
	_ = cmd.MarkFlagRequired("stage")
	return cmd
}

func runGateReset(cmd *cobra.Command, stageID, explicitSessionID, workflowOverride string, workflowExecEnabled, workflowExecSet bool) error {
	ctx, err := loadGateWorkflowContext(workflowOverride, workflowExecEnabled, workflowExecSet)
	if err != nil {
		return err
	}

	resolvedSessionID, source, err := resolveSessionID(explicitSessionID, ctx.workflowName)
	if err != nil {
		return err
	}

	statePath, err := gateSessionStorePath()
	if err != nil {
		return err
	}
	sess, err := session.New(resolvedSessionID, newGateFileBackend(statePath))
	if err != nil {
		return fmt.Errorf("session create: %w", err)
	}
	if err := ctx.runtime.Reset(context.Background(), sess, stageID); err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Reset workflow to stage: %s\n", stageID)
	if source == "flag" {
		fmt.Fprintf(w, "Session: %s\n", resolvedSessionID)
	} else {
		fmt.Fprintf(w, "Session: %s (%s)\n", resolvedSessionID, source)
	}
	fmt.Fprintf(w, "Workflow: %s\n", ctx.workflowName)
	return nil
}
