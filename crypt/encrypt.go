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

func Encrypt(password, srcPath, dstPath string, deleteSrc bool) {
	if password == "" {
		fmt.Printf("Enter password: ")
		passwordByte, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		password = string(passwordByte)
		checkErr(err)
	}
	fmt.Print("\n")
	var err error
	c, err = newCipher(string(password), "")
	checkErr(err)

	fi, err := os.Stat(srcPath)
	checkErr(err)
	if fi.IsDir() {
		encryptDirectory(srcPath, dstPath, deleteSrc)
	} else {
		srcPath, err = filepath.Abs(srcPath)
		checkErr(err)
		os.Chdir(dstPath)
		encryptFile(srcPath, deleteSrc)
	}
}

func encryptFile(path string, deleteSrc bool) {
	data, err := os.ReadFile(path)
	checkErr(err)

	cipherdata, err := c.encryptData(data)
	checkErr(err)

	ciphername := c.encryptName(filepath.Base(path))
	err = os.WriteFile(ciphername, cipherdata, 0664)
	checkErr(err)

//	fmt.Printf("current file: %v\n", path)
//	fmt.Printf("encrypted name: %v\n", ciphername)

	// delete source file after encryption
	if deleteSrc {
		err = os.Remove(path)
		checkErr(err)
	}
}

func encryptDirectory(srcPath, dstPath string, deleteSrc bool) {
	// rsync style trailing slash
	skipRoot := strings.HasSuffix(srcPath, "/")
	// Convert to absolute so unaffected by changing cwd's later
	srcPath, err := filepath.Abs(srcPath)
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
		ciphername := c.encryptName(d.Name())
//		fmt.Printf("current directory: %v\n", path)
//		fmt.Printf("encrypted name: %v\n", ciphername)

		// check if sister of last directory
		if lastDir != "" {
			rel, err := filepath.Rel(lastDir, path)
			checkErr(err)

			if strings.HasPrefix(rel, "..") {
				os.Chdir("..")

				// We only change directories after everything in the last
				// directory has been encrypted. So last directory can been
				// deleted after we've changed directories
				if deleteSrc {
					err = os.Remove(lastDir)
					checkErr(err)
				}

				// After changing directories we might land a file and the
				// direcotry change will not be detected by the below condition
				if !d.IsDir() {
					lastDir = filepath.Dir(path)
				}
			}
		}

		if d.IsDir() {
			lastDir = path
			err = os.Mkdir(ciphername, os.ModePerm)
			checkErr(err)
			os.Chdir(ciphername)
			return nil
		}

		encryptFile(path, deleteSrc)
		return nil
	})
	checkErr(err)

	// Delete the last folder we encrypted
	if deleteSrc {
		err = os.Remove(lastDir)
		checkErr(err)
	}
}
