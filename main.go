package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

func check (e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	password := "Password1234"
	salt := []byte{0xff, 0x56, 0xfe}
	secretKeyBytes, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	check(err)

	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	data, err := os.ReadFile("test/plain")
	check(err)

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	check(err)

	encrypted_data := secretbox.Seal(nonce[:], data, &nonce, &secretKey)
	check(err)

	err = os.WriteFile("test/plain_crypt", encrypted_data, 0664)
	check(err)

	encrypted_file, err := os.ReadFile("test/plain_crypt")
	check(err)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted_file[:24])
	decrypted_data, ok := secretbox.Open(nil, encrypted_file[24:], &decryptNonce, &secretKey)
	if !ok {
		panic("decryption error")
	}

	fmt.Printf("Decrypted: %v", string(decrypted_data))
}
