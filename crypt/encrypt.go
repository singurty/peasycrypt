package crypt

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

var c *Cipher

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func encryptFile(path string) {
	data, err := os.ReadFile(path)
	checkErr(err)

	cipherdata, err := c.encryptData(data)
	checkErr(err)

	err = os.WriteFile(c.encryptName(filepath.Base(path)), cipherdata, 0664)
	checkErr(err)
}

func Encrypt(srcPath, dstPath string) {
	fmt.Printf("Enter password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	checkErr(err)
	fmt.Print("\n")
	c, err = newCipher(string(password), "")
	checkErr(err)

	// rsync style trailing slash
	skipRoot := strings.HasSuffix(srcPath, "/")
	// convert to absolute so unaffected by changing cwd's later
	srcPath, err = filepath.Abs(srcPath)
	checkErr(err)

	err = os.Chdir(dstPath)
	checkErr(err)
	lastDir := ""
	err = filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if srcPath == path && skipRoot {
			return nil
		}
		fmt.Printf("current directory: %v\n", path)
		ciphername := c.encryptName(d.Name())
		fmt.Printf("encrypted name: %v\n", ciphername)

		// check if sister of last directory
		if lastDir != "" {
			rel, err := filepath.Rel(lastDir, path)
			checkErr(err)

			if strings.HasPrefix(rel, "..") {
				os.Chdir("..")
			}
		}

		if d.IsDir() {
			lastDir = path
			err = os.Mkdir(ciphername, os.ModePerm)
			checkErr(err)
			os.Chdir(ciphername)
			return nil
		}

		encryptFile(path)
		return nil
	})
	checkErr(err)
}
