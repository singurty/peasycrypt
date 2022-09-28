package crypt

import (
	"crypto/aes"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/singurty/peasycrypt/crypt/pkcs7"

	"github.com/rfjakob/eme"
)

func (c *Cipher) encryptName(path string) string {
	name := filepath.Base(path)
	if name == "" {
		return ""
	}
	paddedName := pkcs7.Pad(aes.BlockSize, []byte(name))
	emeCipher := eme.New(c.block)
	cipherName := emeCipher.Encrypt(c.nameTweak[:], paddedName)
	return string(cipherName)
}

func EncryptDirectory(srcPath, dstPath string) {
	filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, err error) error {
		fmt.Printf("current directory: %v\n", path)
		return nil
	})
}
