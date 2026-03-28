package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newTestCmd() *cobra.Command {
	var casesPath string
	var callsPath string
	var jsonOutput bool
	var environment string

	cmd := &cobra.Command{
		Use:   "test <bundle>",
		Short: "Run rule test cases",
		Long:  "Evaluate tool calls against a rule bundle using test cases or ad-hoc calls.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if casesPath != "" && callsPath != "" {
				return fmt.Errorf("--cases and --calls are mutually exclusive")
			}
			if casesPath == "" && callsPath == "" {
				return fmt.Errorf("one of --cases or --calls is required")
			}
			if casesPath != "" {
				return runTestCases(cmd, args[0], casesPath, environment, jsonOutput)
			}
			return runTestCalls(cmd, args[0], callsPath, environment, jsonOutput)
		},
	}

	cmd.Flags().StringVar(&casesPath, "cases", "", "YAML file with test cases")
	cmd.Flags().StringVar(&callsPath, "calls", "", "JSON file with tool calls")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&environment, "environment", "production", "environment name")
	return cmd
}

type testCaseFile struct {
	Cases []testCase `yaml:"cases"`
}

type testCase struct {
	ID            string         `yaml:"id"`
	Tool          string         `yaml:"tool"`
	Args          map[string]any `yaml:"args"`
	Expect        string         `yaml:"expect"`
	Principal     *testPrincipal `yaml:"principal"`
	Environment   string         `yaml:"environment"`
	MatchContract string         `yaml:"match_contract"`
}

type testPrincipal struct {
	Role      string `yaml:"role"`
	UserID    string `yaml:"user_id"`
	TicketRef string `yaml:"ticket_ref"`
}

type toolCall struct {
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

func runTestCases(cmd *cobra.Command, bundlePath, casesPath, env string, jsonOut bool) error {
	w := cmd.OutOrStdout()
	g, err := buildGuard([]string{bundlePath}, env)
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("building guard: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("building guard: %w", err)
	}

	raw, err := os.ReadFile(casesPath) //nolint:gosec // Path is caller-provided CLI arg.
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("reading cases file: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("reading cases file: %w", err)
	}

	var cf testCaseFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("parsing cases file: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("parsing cases file: %w", err)
	}

	ctx := context.Background()
	passed := 0
	failed := 0

	type caseResult struct {
		ID       string `json:"id"`
		Tool     string `json:"tool_name"`
		Decision string `json:"decision"`
		Expected string `json:"expected"`
		Passed   bool   `json:"passed"`
		Rule     string `json:"rule,omitempty"`
		Message  string `json:"message,omitempty"`
	}
	var results []caseResult

	for _, tc := range cf.Cases {
		var evalOpts []guard.EvalOption

		caseEnv := env
		if tc.Environment != "" {
			caseEnv = tc.Environment
		}
		evalOpts = append(evalOpts, guard.WithEvalEnvironment(caseEnv))

		if tc.Principal != nil {
			var popts []toolcall.PrincipalOption
			if tc.Principal.Role != "" {
				popts = append(popts, toolcall.WithRole(tc.Principal.Role))
			}
			if tc.Principal.UserID != "" {
				popts = append(popts, toolcall.WithUserID(tc.Principal.UserID))
			}
			if tc.Principal.TicketRef != "" {
				popts = append(popts, toolcall.WithTicketRef(tc.Principal.TicketRef))
			}
			p := toolcall.NewPrincipal(popts...)
			evalOpts = append(evalOpts, guard.WithEvalPrincipal(&p))
		}

		result := g.Evaluate(ctx, tc.Tool, tc.Args, evalOpts...)
		ok := result.Decision == tc.Expect

		if tc.MatchContract != "" && ok {
			ok = matchesDenyContract(result, tc.MatchContract)
		}

		denyContract := extractContractID(result)
		cr := caseResult{
			ID:       tc.ID,
			Tool:     tc.Tool,
			Decision: result.Decision,
			Expected: tc.Expect,
			Passed:   ok,
			Rule:     denyContract,
		}

		if !ok {
			cr.Message = fmt.Sprintf("expected %s", tc.Expect)
			failed++
		} else {
			passed++
		}

		results = append(results, cr)
	}

	if jsonOut {
		return writeJSONTo(w, results)
	}

	for _, cr := range results {
		mark := "+"
		if !cr.Passed {
			mark = "-"
		}
		var line string
		if cr.Rule != "" {
			line = fmt.Sprintf("%s: %s → %s (%s) %s",
				cr.ID, cr.Tool, strings.ToUpper(cr.Decision), cr.Rule, mark)
		} else {
			line = fmt.Sprintf("%s: %s → %s %s",
				cr.ID, cr.Tool, strings.ToUpper(cr.Decision), mark)
		}
		if !cr.Passed {
			line += fmt.Sprintf(" (expected %s)", cr.Expected)
		}
		fmt.Fprintln(w, line)
	}

	fmt.Fprintf(w, "\n%d/%d passed, %d failed\n", passed, len(cf.Cases), failed)

	if failed > 0 {
		return &exitError{code: 1}
	}
	return nil
}

func runTestCalls(cmd *cobra.Command, bundlePath, callsPath, env string, jsonOut bool) error {
	w := cmd.OutOrStdout()
	g, err := buildGuard([]string{bundlePath}, env)
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("building guard: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("building guard: %w", err)
	}

	raw, err := os.ReadFile(callsPath) //nolint:gosec // Path is caller-provided CLI arg.
	if err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("reading calls file: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("reading calls file: %w", err)
	}

	var calls []toolCall
	if err := json.Unmarshal(raw, &calls); err != nil {
		if jsonOut {
			writeErrorJSONTo(w, fmt.Sprintf("parsing calls file: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("parsing calls file: %w", err)
	}

	ctx := context.Background()
	hasDenials := false

	type callResult struct {
		Decision           string   `json:"decision"`
		ToolName           string   `json:"tool_name"`
		ContractsEvaluated int      `json:"contracts_evaluated"`
		DenyReasons        []string `json:"deny_reasons"`
		WarnReasons        []string `json:"warn_reasons"`
	}
	var results []callResult

	for _, call := range calls {
		result := g.Evaluate(ctx, call.Tool, call.Args,
			guard.WithEvalEnvironment(env))

		if result.Decision == "block" {
			hasDenials = true
		}

		results = append(results, callResult{
			Decision:           result.Decision,
			ToolName:           call.Tool,
			ContractsEvaluated: result.ContractsEvaluated,
			DenyReasons:        nonNilStrings(result.DenyReasons),
			WarnReasons:        nonNilStrings(result.WarnReasons),
		})
	}

	if jsonOut {
		return writeJSONTo(w, results)
	}

	fmt.Fprintf(w, "%-3s %-12s %-8s %-10s %s\n", "#", "Tool", "Decision", "Contracts", "Details")
	for i, r := range results {
		details := ""
		if len(r.DenyReasons) > 0 {
			details = strings.Join(r.DenyReasons, "; ")
		}
		fmt.Fprintf(w, "%-3d %-12s %-8s %-10d %s\n",
			i+1, r.ToolName, strings.ToUpper(r.Decision), r.ContractsEvaluated, details)
	}

	if hasDenials {
		return &exitError{code: 1}
	}
	return nil
}

func matchesDenyContract(result guard.EvaluationResult, ruleID string) bool {
	for _, c := range result.Contracts {
		if !c.Passed && c.ContractID == ruleID {
			return true
		}
	}
	return false
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
