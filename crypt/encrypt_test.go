package crypt

import (
	"bytes"
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
	plainData := []byte("hello this is peasycrypt speaking")
	err = os.WriteFile(plainFile, plainData, 0644)
	if err != nil {
		t.Errorf("failed to create plain text file\n")
	}

	os.Chdir(cryptDir)
	encryptFile(plainFile, false)
	os.Chdir(rootDir)

	// Check encrypted filename and data
	cipherFile := filepath.Join(cryptDir, "JEKQ5W7EBBGACXZOCU6QCNFUL4======")
	cipherdata, err := os.ReadFile(cipherFile)
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed to create file with encrypted name")
	} else if err != nil {
		t.Error(err)
	}
	
	decryptedName, err := c.decryptName(filepath.Base(cipherFile))
	if err != nil {
		t.Errorf("failed name decryption: %v", err)
	}
	if decryptedName != filepath.Base(plainFile) {
		t.Errorf("decrypted name mismatch")
	}
	
	// Encryption cannot be changed independently because the nonce is randomly
	// generated. We can test decryption of data and if that works encryption and
	// decryption both works.
	decryptedData, err := c.decryptData(cipherdata)
	if err != nil {
		t.Errorf("failed data decryption: %v", err)
	}
	if bytes.Compare(plainData, decryptedData) != 0 {
		t.Errorf("decrypted data mismatch")
	}

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
