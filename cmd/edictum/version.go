package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the edictum version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			commit := ""
			built := ""
			if bi, ok := debug.ReadBuildInfo(); ok {
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" && len(s.Value) >= 7 {
						commit = s.Value[:7]
					}
					if s.Key == "vcs.time" {
						built = s.Value
					}
				}
			}

			if jsonFlag {
				out := map[string]string{
					"version": edictum.VERSION,
					"go":      runtime.Version(),
					"os":      runtime.GOOS,
					"arch":    runtime.GOARCH,
					"commit":  commit,
					"built":   built,
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				return enc.Encode(out)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "edictum %s\n", edictum.VERSION)
			fmt.Fprintf(cmd.OutOrStdout(), "go %s %s/%s\n",
				runtime.Version(), runtime.GOOS, runtime.GOARCH)
			if commit != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "commit %s\n", commit)
			}
			if built != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "built %s\n", built)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
	return cmd
}
