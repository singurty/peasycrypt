package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "peasycrypt",
		Short: "Encryption made easy peasy.",
	}
)

func Execute() error {
	return rootCmd.Execute()
}
