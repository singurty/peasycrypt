package crypt

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func EncryptDirectory(srcPath, dstPath string) {
	fmt.Printf("Enter password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	checkErr(err)
	fmt.Print("\n")
	c, err := newCipher(string(password), "")
	checkErr(err)

	// rsync style trailing slash
	skipRoot := strings.HasSuffix(srcPath, "/")
	// convert to absolute so unaffected by cwd's later
	srcPath, err = filepath.Abs(srcPath)
	checkErr(err)

	err = filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if srcPath == path && skipRoot {
			return nil
		}
		fmt.Printf("current directory: %v\n", path)
		ciphertext := c.encryptName(path)
		fmt.Printf("encrypted name: %v\n", ciphertext)
		fmt.Printf("decrypted name: %v\n", c.decryptName(ciphertext))
		return nil
	})
	checkErr(err)
}
