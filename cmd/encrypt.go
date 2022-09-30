package cmd

import (
	"github.com/singurty/peasycrypt/crypt"

	"github.com/spf13/cobra"
)

var deleteSrc bool

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptFlags := encryptCmd.Flags()
	encryptFlags.BoolVarP(&deleteSrc, "delete-source", "d", deleteSrc, "Delete original files in src after they have been encrypted to dst.")
}

var encryptCmd = &cobra.Command{
	Use: "encrypt <directory> <destination>",
	Short: "Encrypt a directory.",
	Long: "Encrypt a directory with all its contents. The encrypted content will be at <destination>",
	Args: cobra.ExactArgs(2),
	Run: func(command *cobra.Command, args []string) {
		crypt.Encrypt(args[0], args[1], deleteSrc)
	},
}
