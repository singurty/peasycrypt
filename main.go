package main

import (
_	"crypto/rand"
_	"os"

	"github.com/singurty/peasycrypt/cmd"

_	"golang.org/x/crypto/nacl/secretbox"
_	"golang.org/x/crypto/scrypt"
)

var TEST_FILE = "test/video.mkv"

func check (e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	cmd.Execute()
/**
	password := "Password1234"
	salt := []byte{0xff, 0x56, 0xfe}
	secretKeyBytes, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	check(err)

	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	data, err := os.ReadFile(TEST_FILE)
	check(err)

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	check(err)

	encrypted_data := secretbox.Seal(nonce[:], data, &nonce, &secretKey)
	check(err)

	err = os.WriteFile(TEST_FILE + "_crypt", encrypted_data, 0664)
	check(err)

	encrypted_file, err := os.ReadFile(TEST_FILE + "_crypt")
	check(err)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted_file[:24])
	decrypted_data, ok := secretbox.Open(nil, encrypted_file[24:], &decryptNonce, &secretKey)
	if !ok {
		panic("decryption error")
	}

	err = os.WriteFile(TEST_FILE + "_decrypt", decrypted_data, 0644)
	check(err)
**/
}
