package crypt

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"os"


	"golang.org/x/crypto/ssh/terminal"
)

func EncryptDirectory(srcPath, dstPath string) {
	fmt.Printf("Enter password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		panic(err)
	}
	c, err := newCipher(string(password), "")
	if err != nil {
		panic(err)
	}

	filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, err error) error {
		fmt.Printf("current directory: %v\n", path)
		ciphertext := c.encryptName(path)
		fmt.Printf("encrypted name: %v\n", ciphertext)
		fmt.Printf("decrypted name: %v\n", c.decryptName(ciphertext))
		return nil
	})
}
