// Package main provides the edictum CLI binary.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// exitError signals a non-zero exit code without printing an error message.
// Code 1 = findings/denied, Code 2 = usage/internal error.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("exit %d", e.code)
}

func main() {
	rootCmd := &cobra.Command{
		Use:           "edictum",
		Short:         "Runtime contract enforcement for AI agent tool calls",
		Long:          "Edictum CLI — validate, test, and enforce governance contracts for AI agent tool calls.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(
		newVersionCmd(),
		newValidateCmd(),
		newCheckCmd(),
		newDiffCmd(),
		newReplayCmd(),
		newTestCmd(),
		newGateCmd(),
		newSkillCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
