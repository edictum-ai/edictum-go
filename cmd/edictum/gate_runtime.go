package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/spf13/cobra"
)

func newGateRunCmd() *cobra.Command {
	var (
		format       string
		rulesPath    string
		workflowPath string
		sessionID    string
		workflowExec bool
	)

	cmd := &cobra.Command{
		Use:           "run [flags] -- <command> [args...]",
		Short:         "Execute a tool call through the full Gate runtime",
		Long:          "Run a real tool invocation through Guard.Run(), including session state, workflow gates, and approval handling.",
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workflowExecSet := cmd.Flags().Lookup("workflow-exec").Changed
			return runGateRun(cmd, format, rulesPath, workflowPath, sessionID, workflowExec, workflowExecSet, args)
		},
	}

	cmd.Flags().StringVar(&format, "format", "raw", "input format (claude-code, cursor, copilot, gemini, opencode, raw)")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "override rule path")
	cmd.Flags().StringVar(&workflowPath, "workflow", "", "override workflow path")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "stable session ID for persisted runtime state")
	cmd.Flags().BoolVar(&workflowExec, "workflow-exec", false, "enable trusted exec(...) workflow conditions")
	return cmd
}

func runGateRun(
	cmd *cobra.Command,
	format, rulesOverride, workflowOverride, sessionID string,
	workflowExecEnabled, workflowExecSet bool,
	runnerArgs []string,
) error {
	if sessionID == "" {
		return fmt.Errorf("--session-id is required")
	}
	if len(runnerArgs) == 0 {
		return fmt.Errorf("gate run requires a command after --")
	}

	raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxStdinBytes+1))
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	if len(raw) > maxStdinBytes {
		return fmt.Errorf("stdin input exceeds 10 MB limit")
	}

	toolName, toolArgs, err := parseFormatStdin(format, raw)
	if err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	cfg, cfgErr := loadGateConfigDefault()
	if cfgErr != nil && rulesOverride == "" {
		return fmt.Errorf("no gate config found — run 'edictum gate init'")
	}
	if cfgErr != nil {
		cfg = nil
	}

	rulesPath := rulesOverride
	if rulesPath == "" && cfg != nil {
		rulesPath = cfg.RulesPath
	}
	if rulesPath == "" {
		return fmt.Errorf("no rules configured — pass --rules or run 'edictum gate init'")
	}

	workflowPath := workflowOverride
	if workflowPath == "" && cfg != nil {
		workflowPath = cfg.WorkflowPath
	}
	if !workflowExecSet && cfg != nil {
		workflowExecEnabled = cfg.WorkflowExecEnabled
	}
	if workflowExecEnabled && workflowPath == "" {
		return fmt.Errorf("--workflow-exec requires --workflow or a configured workflow")
	}

	guardCfg := gateGuardConfig{
		RulesPath:           rulesPath,
		WorkflowPath:        workflowPath,
		WorkflowExecEnabled: workflowExecEnabled,
	}
	if cfg != nil {
		guardCfg.ServerURL = cfg.ServerURL
		guardCfg.APIKey = cfg.APIKey
	}

	g, err := buildGateGuard(guardCfg)
	if err != nil {
		return err
	}

	callable, capture := gateSubprocessCallable(runnerArgs, raw)
	result, err := g.Run(context.Background(), toolName, toolArgs, callable, guard.WithSessionID(sessionID))
	if err != nil {
		var blocked *edictum.BlockedError
		if errors.As(err, &blocked) {
			appendGateAuditEvent(cfg, toolName, "block", blocked.Reason)
			return gateRunExit(cmd, blocked.Reason, 1)
		}
		var toolErr *edictum.ToolError
		if errors.As(err, &toolErr) {
			msg := strings.TrimSpace(toolErr.Message)
			if msg == "" {
				msg = "tool execution failed"
			}
			appendGateAuditEvent(cfg, toolName, "allow", msg)
			return gateRunExit(cmd, msg, 1)
		}
		return err
	}
	appendGateAuditEvent(cfg, toolName, "allow", "")

	if capture.stderr != "" {
		if _, err := io.WriteString(cmd.ErrOrStderr(), capture.stderr); err != nil {
			return err
		}
	}
	return writeGateRunResult(cmd.OutOrStdout(), result)
}

func gateRunExit(cmd *cobra.Command, message string, code int) error {
	if message != "" {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), message)
	}
	return &exitError{code: code}
}

func writeGateRunResult(w io.Writer, result any) error {
	switch v := result.(type) {
	case nil:
		return nil
	case string:
		_, err := io.WriteString(w, v)
		return err
	case []byte:
		_, err := w.Write(v)
		return err
	default:
		return json.NewEncoder(w).Encode(v)
	}
}

func appendGateAuditEvent(cfg *gateConfig, toolName, decision, reason string) {
	if cfg == nil || cfg.AuditPath == "" {
		return
	}
	_ = appendWALEvent(cfg.AuditPath, walEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ToolName:  toolName,
		Decision:  decision,
		User:      currentUser(),
		Reason:    reason,
	})
}
