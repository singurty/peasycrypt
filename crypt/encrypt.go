package crypt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

	// Check if the file has already been encrypted by
	// a previous run of peasycrypt
	fi, err := os.Stat(ciphername)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = os.WriteFile(ciphername, cipherdata, 0664)
			checkErr(err)
		} else {
			panic(err)
		}
	} else {
		// Check if the file was finished encrypting in the
		// last run. If not, encrypt it again.
		plainfi, err := os.Stat(path)
		checkErr(err)
		if fi.Size() != encryptedSize(plainfi.Size()) {
			err = os.WriteFile(ciphername, cipherdata, 0664)
			checkErr(err)
		}
	}

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

		// Check if sister or parent of last directory
		if lastDir != "" {
			rel, err := filepath.Rel(lastDir, path)
			checkErr(err)

			if strings.HasPrefix(rel, "..") {
				os.Chdir("..")

				// We only go back a directory after everything in the last
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
			if err != nil && !errors.Is(err, os.ErrExist) {
				panic(err)
			}
			os.Chdir(ciphername)
			return nil
		}

		encryptFile(path, deleteSrc)
		return nil
	})
	checkErr(err)

	if deleteSrc {
		// Delete directores that were empty after the last iteration of the walk loop,
		// but weren't visited again because they were already visited when they had children
		if skipRoot {
			removeContents(srcPath)
		} else {
			err = os.RemoveAll(srcPath)
			checkErr(err)
		}
	}
}

func removeContents(dir string) {
	d, err := os.Open(dir)
	checkErr(err)
	defer d.Close()
	names, err := d.Readdirnames(0)
	checkErr(err)
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		checkErr(err)
    }
}
