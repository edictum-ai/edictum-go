package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/spf13/cobra"
)

func newReplayCmd() *cobra.Command {
	var auditLog string
	var outputPath string

	cmd := &cobra.Command{
		Use:   "replay <bundle>",
		Short: "Replay audit events against contracts",
		Long:  "Re-evaluate historical audit log entries against a contract bundle to detect verdict changes.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if auditLog == "" {
				return fmt.Errorf("--audit-log is required")
			}
			return runReplay(args[0], auditLog, outputPath)
		},
	}

	cmd.Flags().StringVar(&auditLog, "audit-log", "", "path to JSONL audit log file (required)")
	cmd.Flags().StringVar(&outputPath, "output", "", "path for detailed JSONL report")
	return cmd
}

type auditEvent struct {
	ToolName    string         `json:"tool_name"`
	ToolArgs    map[string]any `json:"tool_args"`
	Environment string         `json:"environment"`
	Action      string         `json:"action"`
}

type replayChange struct {
	ToolName     string `json:"tool_name"`
	WasVerdict   string `json:"was_verdict"`
	NowVerdict   string `json:"now_verdict"`
	DenyContract string `json:"deny_contract,omitempty"`
}

type replayReport struct {
	ToolName    string         `json:"tool_name"`
	ToolArgs    map[string]any `json:"tool_args"`
	OldAction   string         `json:"old_action"`
	NewVerdict  string         `json:"new_verdict"`
	Changed     bool           `json:"changed"`
	DenyReasons []string       `json:"deny_reasons,omitempty"`
}

func runReplay(bundlePath, auditLogPath, outputPath string) error {
	g, err := buildGuard([]string{bundlePath}, "production")
	if err != nil {
		return fmt.Errorf("building guard: %w", err)
	}

	f, err := os.Open(auditLogPath) //nolint:gosec // Path is caller-provided CLI arg.
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	ctx := context.Background()
	var changes []replayChange
	var reports []replayReport
	total := 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue // skip malformed lines
		}
		if event.ToolName == "" {
			continue
		}

		total++

		var evalOpts []guard.EvalOption
		if event.Environment != "" {
			evalOpts = append(evalOpts, guard.WithEvalEnvironment(event.Environment))
		}

		result := g.Evaluate(ctx, event.ToolName, event.ToolArgs, evalOpts...)

		oldVerdict := actionToVerdict(event.Action)
		changed := result.Verdict != oldVerdict

		if changed {
			change := replayChange{
				ToolName:   event.ToolName,
				WasVerdict: strings.ToUpper(oldVerdict),
				NowVerdict: strings.ToUpper(result.Verdict),
			}
			if result.Verdict == "deny" && len(result.DenyReasons) > 0 {
				change.DenyContract = extractContractID(result)
			}
			changes = append(changes, change)
		}

		if outputPath != "" {
			reports = append(reports, replayReport{
				ToolName:    event.ToolName,
				ToolArgs:    event.ToolArgs,
				OldAction:   event.Action,
				NewVerdict:  result.Verdict,
				Changed:     changed,
				DenyReasons: result.DenyReasons,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}

	if outputPath != "" {
		if err := writeReplayReport(outputPath, reports); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	printReplaySummary(total, changes)

	if len(changes) > 0 {
		return &exitError{code: 1}
	}
	return nil
}

func actionToVerdict(action string) string {
	switch action {
	case "call_allowed":
		return "allow"
	case "call_denied":
		return "deny"
	default:
		return action
	}
}

func extractContractID(result guard.EvaluationResult) string {
	for _, c := range result.Contracts {
		if !c.Passed && c.ContractID != "" {
			return c.ContractID
		}
	}
	return ""
}

func printReplaySummary(total int, changes []replayChange) {
	fmt.Printf("Replayed %d events, %d would change\n", total, len(changes))
	if len(changes) == 0 {
		return
	}
	fmt.Println()
	for _, c := range changes {
		line := fmt.Sprintf("  tool_name: %s → was %s, now %s",
			c.ToolName, c.WasVerdict, c.NowVerdict)
		if c.DenyContract != "" {
			line += " by " + c.DenyContract
		}
		fmt.Println(line)
	}
}

func writeReplayReport(path string, reports []replayReport) error {
	f, err := os.Create(path) //nolint:gosec // Output path is caller-provided CLI arg.
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, r := range reports {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
