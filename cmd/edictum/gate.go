package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/edictum-ai/edictum-go/guard"
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
		contractsPath  string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up Edictum Gate governance",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateInit(cmd, serverURL, apiKey, contractsPath, nonInteractive)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Console server URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Console API key")
	cmd.Flags().StringVar(&contractsPath, "contracts", "", "custom ContractBundle YAML")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip prompts, use defaults")
	return cmd
}

func runGateInit(cmd *cobra.Command, serverURL, apiKey, contractsPath string, _ bool) error {
	gateDir, err := gateDirectory()
	if err != nil {
		return err
	}

	dirs := []string{
		gateDir,
		filepath.Join(gateDir, "contracts"),
		filepath.Join(gateDir, "audit"),
	}
	for _, d := range dirs {
		if mkErr := os.MkdirAll(d, 0o755); mkErr != nil {
			return fmt.Errorf("creating %s: %w", d, mkErr)
		}
	}

	cfg := &gateConfig{
		ServerURL:     serverURL,
		APIKey:        apiKey,
		ContractsPath: filepath.Join(gateDir, "contracts"),
		AuditPath:     filepath.Join(gateDir, "audit"),
	}

	if contractsPath != "" {
		dst := filepath.Join(gateDir, "contracts", filepath.Base(contractsPath))
		if cpErr := copyFile(contractsPath, dst); cpErr != nil {
			return fmt.Errorf("copying contracts: %w", cpErr)
		}
		if _, buildErr := guard.FromYAML(dst); buildErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: contracts validation failed: %s\n", buildErr)
		}
	}

	configPath := filepath.Join(gateDir, "config.json")
	if wErr := writeGateConfig(configPath, cfg); wErr != nil {
		return fmt.Errorf("writing config: %w", wErr)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Edictum Gate initialized.")
	fmt.Fprintf(w, "  Config:    %s\n", configPath)
	fmt.Fprintf(w, "  Contracts: %s\n", cfg.ContractsPath)
	fmt.Fprintf(w, "  Audit:     %s\n", cfg.AuditPath)
	if serverURL != "" {
		fmt.Fprintf(w, "  Server:    %s\n", serverURL)
	}
	return nil
}

func newGateCheckCmd() *cobra.Command {
	var (
		format        string
		contractsPath string
		jsonFlag      bool
	)

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate a tool call from stdin against contracts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateCheck(cmd, format, contractsPath, jsonFlag)
		},
	}

	cmd.Flags().StringVar(&format, "format", "claude-code", "output format (claude-code, cursor, copilot, gemini, opencode, raw)")
	cmd.Flags().StringVar(&contractsPath, "contracts", "", "override contract path")
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "force JSON output")
	return cmd
}

func runGateCheck(cmd *cobra.Command, format, contractsOverride string, jsonFlag bool) error {
	if jsonFlag {
		format = "raw"
	}

	raw, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		msg := fmt.Sprintf("reading stdin: %s", err)
		if format == "raw" {
			_ = writeGateError(cmd, msg)
			return &exitError{code: 2}
		}
		return fmt.Errorf("%s", msg)
	}

	toolName, toolArgs, parseErr := parseFormatStdin(format, raw)
	if parseErr != nil {
		msg := fmt.Sprintf("parsing input: %s", parseErr)
		if format == "raw" {
			_ = writeGateError(cmd, msg)
			return &exitError{code: 2}
		}
		return fmt.Errorf("%s", msg)
	}

	cPath := contractsOverride
	if cPath == "" {
		cfg, cfgErr := loadGateConfigDefault()
		if cfgErr != nil {
			msg := fmt.Sprintf("loading config: %s", cfgErr)
			if format == "raw" {
				_ = writeGateError(cmd, msg)
				return &exitError{code: 2}
			}
			return fmt.Errorf("%s", msg)
		}
		cPath = cfg.ContractsPath
	}

	g, gErr := buildGuardFromPath(cPath)
	if gErr != nil {
		msg := fmt.Sprintf("loading contracts: %s", gErr)
		if format == "raw" {
			_ = writeGateError(cmd, msg)
			return &exitError{code: 2}
		}
		return fmt.Errorf("%s", msg)
	}

	ctx := context.Background()
	result := g.Evaluate(ctx, toolName, toolArgs)

	contractID := extractContractID(result)
	reason := ""
	if len(result.DenyReasons) > 0 {
		reason = result.DenyReasons[0]
	}

	// Append audit event.
	if cfg, cfgErr := loadGateConfigDefault(); cfgErr == nil && cfg.AuditPath != "" {
		_ = appendWALEvent(cfg.AuditPath, walEvent{
			ToolName: toolName,
			Verdict:  result.Verdict,
			User:     currentUser(),
			Detail:   reason,
			Reason:   reason,
		})
	}

	if result.Verdict == "deny" {
		if wErr := writeCheckDeny(cmd, format, buildDenyReason(contractID, reason)); wErr != nil {
			return wErr
		}
		return &exitError{code: 1}
	}

	return writeCheckOutput(cmd, format, "allow", "", "")
}

// writeGateError outputs a structured JSON error for gate check.
func writeGateError(cmd *cobra.Command, msg string) error {
	out := map[string]any{"error": msg, "decision": "error"}
	enc := json.NewEncoder(cmd.OutOrStdout())
	return enc.Encode(out)
}
