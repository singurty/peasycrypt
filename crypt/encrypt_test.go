package crypt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var rootDir string
var testDir string
var plainDir string
var cryptDir string

func TestMain(m *testing.M) {
	// Setup test paths
	var err error
	rootDir, err = filepath.Abs(".")
	if err != nil {
		panic(err)
	}
	testDir, err = filepath.Abs("testdata")
	if err != nil {
		panic(err)
	}
	plainDir, err = filepath.Abs("testdata/plain")
	if err != nil {
		panic(err)
	}
	cryptDir, err = filepath.Abs("testdata/crypt")
	if err != nil {
		panic(err)
	}
	// Setup cipher
	c, err = newCipher("", "")
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestEncryptFile(t *testing.T) {
	err := createTestDirs()
	if err != nil {
		t.Errorf("failed to create test dirs\n")
	}
	
	plainFile := filepath.Join(plainDir, "hello.txt")
	data := []byte("hello this is peasycrypt speaking")
	err = os.WriteFile(plainFile, data, 0644)
	if err != nil {
		t.Errorf("failed to create plain text file\n")
	}

	os.Chdir(cryptDir)
	encryptFile(plainFile, false)
	os.Chdir(rootDir)

	// Check encrypted filename and data
	cipherFile := filepath.Join(cryptDir, "JEKQ5W7EBBGACXZOCU6QCNFUL4======")
	_, err = os.ReadFile(cipherFile)
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed to create file with encrypted name")
	} else if err != nil {
		t.Error(err)
	}
	
	// Check if the file data encrypted correctly
	// (will be added after decryption is implemented)

	err = removeTestDirs()
	if err != nil {
		t.Errorf("failed to remove test dirs\n")
	}
}

func createTestDirs() error {
	err := os.MkdirAll(plainDir, os.ModePerm)
	if err != nil {
		return err
	}
	return os.MkdirAll(cryptDir, os.ModePerm)
}

func removeTestDirs() error {
	return os.RemoveAll(testDir)
}
