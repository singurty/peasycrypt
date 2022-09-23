package crypt

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

func EncryptDirectory(srcPath, dstPath string) {
	filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, err error) error {
		fmt.Printf("current directory: %v\n", path)
		return nil
	})
}
