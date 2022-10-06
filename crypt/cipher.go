package crypt

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/singurty/peasycrypt/crypt/pkcs7"
)

const (
	nonceSize = 24
	headerSize = nonceSize + secretbox.Overhead
)

// Errors returned by cipher
var (
	ErrorBadBase32Encoding = errors.New("bad base32 filename encoding")
)

var defaultSalt = []byte{0xff, 0x56, 0xfe, 0x37, 0x99, 0x2f}

// The standard base32 encoding is modified in two ways
//  * it becomes lower case (no-one likes upper case filenames!)
//  * we strip the padding character `=`

// EncodeToString encodes a strign using the modified version of
// base32 encoding.
func encodeToString(src []byte) string {
	encoded := base32.HexEncoding.EncodeToString(src)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded)
}

// DecodeString decodes a string as encoded by EncodeToString
func decodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, ErrorBadBase32Encoding
	}
	// First figure out how many padding characters to add
	roundUpToMultipleOf8 := (len(s) + 7) &^ 7
	equals := roundUpToMultipleOf8 - len(s)
	s = strings.ToUpper(s) + "========"[:equals]
	return base32.HexEncoding.DecodeString(s)
}

type Cipher struct {
	dataKey [32]byte
	nameKey [32]byte
	nameTweak [aes.BlockSize]byte
	block gocipher.Block
}

func NewCipher(password, salt string) (*Cipher, error) {
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

func (c *Cipher) encryptName(name string) string {
	if name == "" {
		return ""
	}
	paddedName := pkcs7.Pad(aes.BlockSize, []byte(name))
	emeCipher := eme.New(c.block)
	cipherName := emeCipher.Encrypt(c.nameTweak[:], paddedName)
	return encodeToString(cipherName)
}

func (c *Cipher) decryptName(ciphertext string) (string, error) {
	cipherbytes, err := decodeString(ciphertext)
	if err != nil {
		return "", err
	}

	emeCipher := eme.New(c.block)
	paddedName := emeCipher.Decrypt(c.nameTweak[:], cipherbytes)
	unpaddedName, err := pkcs7.Unpad(aes.BlockSize, paddedName)
	return string(unpaddedName), nil
}

func (c *Cipher) encryptData(plaindata []byte) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	encrypted_data := secretbox.Seal(nonce[:], plaindata, &nonce, &c.dataKey)
	return encrypted_data, nil
}

func (c *Cipher) decryptData(cipherdata []byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], cipherdata[:24])
	decryptedData, ok := secretbox.Open(nil, cipherdata[24:], &decryptNonce, &c.dataKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decryptedData, nil
}

func encryptedSize(size int64) int64 {
	return size + headerSize
}
