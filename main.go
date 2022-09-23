package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"crypto/rand"
)

func check (e error) {
	if e != nil {
		panic(e)
	}
}

func encrypt(data []byte, password string) ([]byte, error) {
	if len(data) % aes.BlockSize != 0 {
		panic("blocksize mismatch")
	}
	block, err := aes.NewCipher([]byte (password))
	
	if err != nil {
		return nil, err
	}

	cipertext := make([]byte, aes.BlockSize + len(data))
	iv := cipertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipertext[aes.BlockSize:], data)

	return cipertext, nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	block, err := aes.NewCipher(([]byte (password)))
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		panic("encrypted data too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext) % aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func main() {
	password := "pppppppppppppppppppppppppppppppp"
	data, err := os.ReadFile("test/plain")
	check(err)

	encrypted_data, err := encrypt(data, password)
	check(err)

	err = os.WriteFile("test/plain_crypt", encrypted_data, 0664)
	check(err)

	encrypted_file, err := os.ReadFile("test/plain_crypt")
	check(err)

	decrypted_data, err := decrypt(encrypted_file, password)
	fmt.Printf("Decrypted: %v\n", string(decrypted_data))
}
