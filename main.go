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
}
