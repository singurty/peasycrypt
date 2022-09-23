package cmd

import (
	"github.com/singurty/peasycrypt/crypt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
}

var encryptCmd = &cobra.Command{
	Use: "encrypt <directory> <destination>",
	Short: "Encrypt a directory.",
	Long: "Encrypt a directory with all its contents. The encrypted content will be at <destination>",
	Args: cobra.ExactArgs(2),
	Run: func(command *cobra.Command, args []string) {
		crypt.EncryptDirectory(args[0], args[1])
	},
}
