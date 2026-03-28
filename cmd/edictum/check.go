package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/spf13/cobra"
)

func newCheckCmd() *cobra.Command {
	var (
		toolName        string
		argsJSON        string
		principalRole   string
		principalUser   string
		principalTicket string
		environment     string
		jsonOutput      bool
	)

	cmd := &cobra.Command{
		Use:   "check <files...>",
		Short: "Evaluate a tool call against rule bundles",
		Long:  "Evaluate a tool call offline against one or more YAML rule bundles.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, files []string) error {
			return runCheck(cmd, files, checkArgs{
				toolName:        toolName,
				argsJSON:        argsJSON,
				principalRole:   principalRole,
				principalUser:   principalUser,
				principalTicket: principalTicket,
				environment:     environment,
				jsonOutput:      jsonOutput,
			})
		},
	}

	cmd.Flags().StringVar(&toolName, "tool", "", "tool name (required)")
	cmd.Flags().StringVar(&argsJSON, "args", "", "tool arguments as JSON (required)")
	cmd.Flags().StringVar(&principalRole, "principal-role", "", "principal role")
	cmd.Flags().StringVar(&principalUser, "principal-user", "", "principal user ID")
	cmd.Flags().StringVar(&principalTicket, "principal-ticket", "", "principal ticket ref")
	cmd.Flags().StringVar(&environment, "environment", "production", "environment name")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")

	_ = cmd.MarkFlagRequired("tool")
	_ = cmd.MarkFlagRequired("args")

	return cmd
}

type checkArgs struct {
	toolName        string
	argsJSON        string
	principalRole   string
	principalUser   string
	principalTicket string
	environment     string
	jsonOutput      bool
}

func runCheck(cmd *cobra.Command, files []string, ca checkArgs) error {
	w := cmd.OutOrStdout()
	var args map[string]any
	if err := json.Unmarshal([]byte(ca.argsJSON), &args); err != nil {
		if ca.jsonOutput {
			writeErrorJSONTo(w, fmt.Sprintf("invalid --args JSON: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("invalid --args JSON: %w", err)
	}

	g, err := buildGuardFromFiles(files, ca.environment)
	if err != nil {
		if ca.jsonOutput {
			writeErrorJSONTo(w, fmt.Sprintf("loading rules: %s", err)) //nolint:errcheck // best-effort JSON error
			return &exitError{code: 2}
		}
		return fmt.Errorf("loading rules: %w", err)
	}

	var evalOpts []guard.EvalOption
	if ca.principalRole != "" || ca.principalUser != "" || ca.principalTicket != "" {
		p := buildPrincipal(ca.principalRole, ca.principalUser, ca.principalTicket)
		evalOpts = append(evalOpts, guard.WithEvalPrincipal(&p))
	}

	ctx := context.Background()
	result := g.Evaluate(ctx, ca.toolName, args, evalOpts...)

	if ca.jsonOutput {
		return printCheckJSON(cmd, ca, result)
	}
	return printCheckText(cmd, result)
}

func buildPrincipal(role, user, ticket string) toolcall.Principal {
	var opts []toolcall.PrincipalOption
	if role != "" {
		opts = append(opts, toolcall.WithRole(role))
	}
	if user != "" {
		opts = append(opts, toolcall.WithUserID(user))
	}
	if ticket != "" {
		opts = append(opts, toolcall.WithTicketRef(ticket))
	}
	return toolcall.NewPrincipal(opts...)
}

type checkOutput struct {
	Tool               string         `json:"tool"`
	Args               map[string]any `json:"args"`
	Decision           string         `json:"decision"`
	Reason             string         `json:"reason,omitempty"`
	ContractsEvaluated int            `json:"contracts_evaluated"`
	Environment        string         `json:"environment"`
	ContractID         string         `json:"contract_id,omitempty"`
}

func printCheckJSON(cmd *cobra.Command, ca checkArgs, r guard.EvaluationResult) error {
	var args map[string]any
	_ = json.Unmarshal([]byte(ca.argsJSON), &args)

	out := checkOutput{
		Tool:               ca.toolName,
		Args:               args,
		Decision:           r.Decision,
		ContractsEvaluated: r.ContractsEvaluated,
		Environment:        ca.environment,
	}

	if r.Decision == "block" && len(r.DenyReasons) > 0 {
		out.Reason = r.DenyReasons[0]
	} else if r.Decision == "warn" && len(r.WarnReasons) > 0 {
		out.Reason = r.WarnReasons[0]
	}

	// Find the first failing rule ID.
	for _, c := range r.Contracts {
		if !c.Passed {
			out.ContractID = c.ContractID
			break
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("json encode: %w", err)
	}

	if r.Decision == "block" {
		return &exitError{code: 1}
	}
	return nil
}

func printCheckText(cmd *cobra.Command, r guard.EvaluationResult) error { //nolint:errcheck // CLI output
	w := cmd.OutOrStdout()

	if r.Decision == "block" {
		for _, c := range r.Contracts {
			if !c.Passed {
				fmt.Fprintf(w, "\u2717 DENIED by %s", c.ContractID)
				if c.Message != "" {
					fmt.Fprintf(w, " \u2014 %s", c.Message)
				}
				fmt.Fprintln(w)
			}
		}
		return &exitError{code: 1}
	}

	if r.Decision == "warn" {
		for _, reason := range r.WarnReasons {
			fmt.Fprintf(w, "! WARN: %s\n", reason)
		}
	}

	fmt.Fprintf(w, "\u2713 ALLOWED (%d rules evaluated)\n", r.ContractsEvaluated)
	return nil
}
