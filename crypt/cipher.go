package crypt

import (
	"crypto/aes"
	"golang.org/x/crypto/scrypt"
	gocipher "crypto/cipher"
	"path/filepath"
	"encoding/base64"

	"github.com/singurty/peasycrypt/crypt/pkcs7"

	"github.com/rfjakob/eme"
)

var defaultSalt = []byte{0xff, 0x56, 0xfe, 0x37, 0x99, 0x2f}

type Cipher struct {
	dataKey [32]byte
	nameKey [32]byte
	nameTweak [aes.BlockSize]byte
	block gocipher.Block
}

func newCipher(password, salt string) (*Cipher, error) {
	c := &Cipher{}
	err := c.key(password, salt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) key(password, salt string) (err error) {
	keySize := len(c.dataKey) + len(c.nameKey) + len(c.nameTweak)
	var saltBytes []byte
	if salt != "" {
		saltBytes = []byte(salt)
	} else {
		saltBytes = defaultSalt
	}
	key, err := scrypt.Key([]byte(password), saltBytes, 32768, 8, 1, keySize)

	copy(c.dataKey[:], key)
	copy(c.nameKey[:], key[len(c.dataKey):])
	copy(c.nameTweak[:], key[len(c.dataKey)+len(c.nameKey):])

	// create name cipher
	c.block, err = aes.NewCipher(c.nameKey[:])
	return err
}

func (c *Cipher) encryptName(path string) string {
	name := filepath.Base(path)
	if name == "" {
		return ""
	}
	paddedName := pkcs7.Pad(aes.BlockSize, []byte(name))
	emeCipher := eme.New(c.block)
	cipherName := emeCipher.Encrypt(c.nameTweak[:], paddedName)
	return base64.RawStdEncoding.EncodeToString(cipherName)
}

func (c *Cipher) decryptName(ciphertext string) string {
	cipherbytes, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}

	emeCipher := eme.New(c.block)
	paddedName := emeCipher.Decrypt(c.nameTweak[:], cipherbytes)
	unpaddedName, err := pkcs7.Unpad(aes.BlockSize, paddedName)
	return string(unpaddedName)
}
