package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "oss-risk-guard",
		Short: "Open source risk scanning",
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "score [path]",
		Short: "Scan a project for open source risks",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Scanning: %s\n", args[0])
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
