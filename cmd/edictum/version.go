package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the edictum version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "edictum %s\n", edictum.VERSION)
			fmt.Fprintf(cmd.OutOrStdout(), "go %s %s/%s\n",
				runtime.Version(), runtime.GOOS, runtime.GOARCH)

			if bi, ok := debug.ReadBuildInfo(); ok {
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" && len(s.Value) >= 7 {
						fmt.Fprintf(cmd.OutOrStdout(), "commit %s\n", s.Value[:7])
					}
					if s.Key == "vcs.time" {
						fmt.Fprintf(cmd.OutOrStdout(), "built %s\n", s.Value)
					}
				}
			}
			return nil
		},
	}
}
