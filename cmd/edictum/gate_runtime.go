package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/server"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
	"github.com/spf13/cobra"
)

const gateApprovalPollInterval = 100 * time.Millisecond

type gateGuardConfig struct {
	RulesPath           string
	WorkflowPath        string
	WorkflowExecEnabled bool
	ServerURL           string
	APIKey              string
}

type gateSubprocessCapture struct {
	stderr string
}

func newGateRunCmd() *cobra.Command {
	var (
		format       string
		contracts    string
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
			return runGateRun(cmd, format, contracts, workflowPath, sessionID, workflowExec, workflowExecSet, args)
		},
	}

	cmd.Flags().StringVar(&format, "format", "raw", "input format (claude-code, cursor, copilot, gemini, opencode, raw)")
	cmd.Flags().StringVar(&contracts, "rules", "", "override rule path")
	cmd.Flags().StringVar(&workflowPath, "workflow", "", "override workflow path")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "stable session ID for persisted runtime state")
	cmd.Flags().BoolVar(&workflowExec, "workflow-exec", false, "enable trusted exec(...) workflow conditions")
	return cmd
}

func runGateRun(
	cmd *cobra.Command,
	format, contractsOverride, workflowOverride, sessionID string,
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
	if cfgErr != nil && contractsOverride == "" {
		return fmt.Errorf("no gate config found — run 'edictum gate init'")
	}
	if cfgErr != nil {
		cfg = nil
	}

	rulesPath := contractsOverride
	if rulesPath == "" && cfg != nil {
		rulesPath = cfg.ContractsPath
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
			return gateRunExit(cmd, blocked.Reason, 1)
		}
		var toolErr *edictum.ToolError
		if errors.As(err, &toolErr) {
			msg := strings.TrimSpace(toolErr.Message)
			if msg == "" {
				msg = "tool execution failed"
			}
			return gateRunExit(cmd, msg, 1)
		}
		return err
	}

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

func buildGateGuard(cfg gateGuardConfig) (*guard.Guard, error) {
	statePath, err := gateSessionStorePath()
	if err != nil {
		return nil, err
	}
	backend := newGateFileBackend(statePath)

	approvalBackend, err := newGateApprovalBackend(cfg.ServerURL, cfg.APIKey)
	if err != nil {
		return nil, err
	}

	return buildGateGuardWithDeps(cfg, backend, approvalBackend)
}

func buildGateGuardWithDeps(cfg gateGuardConfig, backend session.StorageBackend, approvalBackend approval.Backend) (*guard.Guard, error) {
	if cfg.RulesPath == "" {
		return nil, fmt.Errorf("no rules configured")
	}

	opts := []guard.Option{guard.WithBackend(backend)}
	if approvalBackend != nil {
		opts = append(opts, guard.WithApprovalBackend(approvalBackend))
	}
	if cfg.WorkflowPath != "" {
		rt, err := loadGateWorkflowRuntime(cfg.WorkflowPath, cfg.WorkflowExecEnabled)
		if err != nil {
			return nil, err
		}
		opts = append(opts, guard.WithWorkflowRuntime(rt))
	}

	g, err := guard.FromYAML(cfg.RulesPath, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}
	return g, nil
}

func loadGateWorkflowRuntime(path string, execEnabled bool) (*workflow.Runtime, error) {
	def, err := workflow.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading workflow: %w", err)
	}
	var opts []workflow.RuntimeOption
	if execEnabled {
		opts = append(opts, workflow.WithExecEvaluatorEnabled())
	}
	rt, err := workflow.NewRuntime(def, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading workflow: %w", err)
	}
	return rt, nil
}

func newGateApprovalBackend(serverURL, apiKey string) (approval.Backend, error) {
	if serverURL == "" {
		return nil, nil
	}

	client, err := server.NewClient(server.ClientConfig{
		BaseURL: serverURL,
		APIKey:  apiKey,
		AgentID: "gate-cli",
		Env:     "production",
	})
	if err != nil {
		return nil, fmt.Errorf("configuring approval backend: %w", err)
	}
	return server.NewApprovalBackend(client, server.WithPollInterval(gateApprovalPollInterval)), nil
}

func gateSessionStorePath() (string, error) {
	gateDir, err := gateDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(gateDir, "state", "sessions.json"), nil
}

func gateSubprocessCallable(runnerArgs []string, raw []byte) (func(map[string]any) (any, error), *gateSubprocessCapture) {
	capture := &gateSubprocessCapture{}
	return func(_ map[string]any) (any, error) {
		proc := exec.Command(runnerArgs[0], runnerArgs[1:]...) //nolint:gosec // Child command is the explicit CLI API.
		proc.Stdin = bytes.NewReader(raw)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		proc.Stdout = &stdout
		proc.Stderr = &stderr

		err := proc.Run()
		capture.stderr = stderr.String()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = strings.TrimSpace(stdout.String())
			}
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("%s", msg)
		}

		return stdout.String(), nil
	}, capture
}

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
