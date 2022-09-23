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

func main() {
	password := "pppppppppppppppppppppppppppppppp"
	data, err := os.ReadFile("test/plain")
	check(err)

	if len(data) % aes.BlockSize != 0 {
		panic("blocksize mismatch")
	}
	block, err := aes.NewCipher([]byte (password))
	check(err)

	cipertext := make([]byte, aes.BlockSize + len(data))
	iv := cipertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipertext[aes.BlockSize:], data)

	fmt.Printf("%x\n", cipertext)
}
