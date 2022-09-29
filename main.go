package main

import (
_	"crypto/rand"
_	"os"

	"github.com/singurty/peasycrypt/cmd"

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
