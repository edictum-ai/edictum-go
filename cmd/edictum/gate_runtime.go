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
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
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
		Long:          "Run a real tool call through Guard.Run(), including session state, workflow gates, and approval handling.",
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

	workflowName := ""
	if workflowPath != "" {
		rt, err := loadGateWorkflowRuntime(workflowPath, workflowExecEnabled)
		if err != nil {
			return err
		}
		workflowName = rt.Definition().Metadata.Name
	}

	resolvedSessionID, sessionSource, err := resolveSessionID(sessionID, workflowName)
	if err != nil {
		return err
	}
	if sessionSource != "flag" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Using session: %s (%s)\n", resolvedSessionID, sessionSource)
	}

	guardCfg := gateGuardConfig{
		RulesPath:           rulesPath,
		WorkflowPath:        workflowPath,
		WorkflowExecEnabled: workflowExecEnabled,
	}
	if cfg != nil {
		guardCfg.Environment = cfg.Environment
		guardCfg.ServerURL = cfg.ServerURL
		guardCfg.APIKey = cfg.APIKey
	}

	g, err := buildGateGuard(guardCfg)
	if err != nil {
		return err
	}

	callable, capture := gateSubprocessCallable(runnerArgs, raw)
	result, err := g.Run(context.Background(), toolName, toolArgs, callable, guard.WithSessionID(resolvedSessionID))
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
		appendGateAuditEvent(cfg, toolName, "block", "gate run internal error: "+err.Error())
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

type gateWorkflowRuntimeContext struct {
	cfg          *gateConfig
	workflowPath string
	workflowName string
	runtime      *workflow.Runtime
}

type gateWorkflowStateSnapshot struct {
	State  workflow.State
	Exists bool
}

func loadGateWorkflowContext(workflowOverride string, workflowExecEnabled, workflowExecSet bool) (*gateWorkflowRuntimeContext, error) {
	cfg, cfgErr := loadGateConfigDefault()
	if cfgErr != nil && workflowOverride == "" {
		return nil, fmt.Errorf("no gate config found — run 'edictum gate init'")
	}
	if cfgErr != nil {
		cfg = nil
	}

	workflowPath := workflowOverride
	if workflowPath == "" && cfg != nil {
		workflowPath = cfg.WorkflowPath
	}
	if !workflowExecSet && cfg != nil {
		workflowExecEnabled = cfg.WorkflowExecEnabled
	}
	if workflowExecEnabled && workflowPath == "" {
		return nil, fmt.Errorf("--workflow-exec requires --workflow or a configured workflow")
	}
	if workflowPath == "" {
		return nil, fmt.Errorf("no workflow configured — pass --workflow or run 'edictum gate init --workflow <path>'")
	}

	rt, err := loadGateWorkflowRuntime(workflowPath, workflowExecEnabled)
	if err != nil {
		return nil, err
	}

	return &gateWorkflowRuntimeContext{
		cfg:          cfg,
		workflowPath: workflowPath,
		workflowName: rt.Definition().Metadata.Name,
		runtime:      rt,
	}, nil
}

func loadGateWorkflowStateSnapshot(rt *workflow.Runtime, sessionID string) (gateWorkflowStateSnapshot, error) {
	statePath, err := gateSessionStorePath()
	if err != nil {
		return gateWorkflowStateSnapshot{}, err
	}
	sess, err := session.New(sessionID, newGateFileBackend(statePath))
	if err != nil {
		return gateWorkflowStateSnapshot{}, err
	}
	raw, err := sess.GetValue(context.Background(), workflowStateStorageKey(rt.Definition().Metadata.Name))
	if err != nil {
		return gateWorkflowStateSnapshot{}, err
	}
	if raw == "" {
		return gateWorkflowStateSnapshot{Exists: false}, nil
	}
	state, err := rt.State(context.Background(), sess)
	if err != nil {
		return gateWorkflowStateSnapshot{}, err
	}
	return gateWorkflowStateSnapshot{
		State:  state,
		Exists: true,
	}, nil
}

func workflowStateStorageKey(workflowName string) string {
	return "workflow:" + workflowName + ":state"
}
