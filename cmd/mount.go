package cmd

import (
	"github.com/singurty/peasycrypt/mount"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mountCmd)
}

var mountCmd = &cobra.Command{
	Use: "mount <directory> <mountpoint>",
	Short: "Mount an encrypted directory.",
	Long: "Encrypt a directory with all its contents. The encrypted content will be at <destination>",
	Args: cobra.ExactArgs(2),
	Run: func(command *cobra.Command, args []string) {
		mount.Mount(args[0], args[1])
	},
}
