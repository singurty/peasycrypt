package crypt

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	 createTestDirs(t)
	
	plainFile := filepath.Join(plainDir, "hello.txt")
	plainData := []byte("hello this is peasycrypt speaking")
	createFile(plainFile, plainData, t)

	os.Chdir(cryptDir)
	encryptFile(plainFile, false)

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

	// Since deleteSrc was set to false, the original file should still exist
	exist, err := doesFileExist(plainFile)
	if !exist {
		if err == nil {
			t.Errorf("file deleted when deleteSrc set to false")
		} else {
			t.Error(err)
		}
	}
	
	// Original file should be deleted when deleteSrc is set to true
	encryptFile(plainFile, true)
	exist, err = doesFileExist(plainFile)
	if exist {
		t.Errorf("file not deleted when deleteSrc set to false")
	} else if err != nil {
		t.Error(err)
	}

	os.Chdir(rootDir)
	removeTestDirs(t)
}

func TestEncrypt(t *testing.T) {
	createTestDirs(t)

	err := os.MkdirAll(filepath.Join(plainDir, "/writings/nicer"), os.ModePerm)
	if err != nil {
		t.Error(err)
	}

	createFile(filepath.Join(plainDir, "writings/hello.txt"), []byte("hello"), t)
	createFile(filepath.Join(plainDir, "writings/hi.txt"), []byte("hi"), t)
	createFile(filepath.Join(plainDir, "writings/nicer/nicehello.txt"), []byte("nice hello"), t)
	createFile(filepath.Join(plainDir, "writings/nicer/nicehi.txt"), []byte("nice hi"), t)

	expectedTreeWithoutRoot := []string{
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======",
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======/CGCJTJLM4JNSAPOXNGM3GKQKLM======",
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======/GHNM7O5RFLH3JLTVAA7NYKIZWU======",
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======/GHNM7O5RFLH3JLTVAA7NYKIZWU======/HLIZPUQ5XCYEIIWTRMJ5INV7GA======",
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======/GHNM7O5RFLH3JLTVAA7NYKIZWU======/X53HPKF55O2L6X4S54PP2JUMJU======",
		"DLLEA4TLUPRHUQQUQZUDTSWIW4======/JEKQ5W7EBBGACXZOCU6QCNFUL4======",
	}
	expectedTreeWithRoot := make([]string, len(expectedTreeWithoutRoot) + 1)
	expectedTreeWithRoot[0] = "JNKKS57W7VHCCRMRVTO6FW4SCE======"
	for i, withoutRoot := range expectedTreeWithoutRoot {
		withRoot := filepath.Join("JNKKS57W7VHCCRMRVTO6FW4SCE======", withoutRoot)
		expectedTreeWithRoot[i+1] = withRoot
	}

	encryptDirectory(plainDir + "/", cryptDir, true)
	checkDirTree(t, cryptDir, expectedTreeWithoutRoot)

	// Test again without omitting the root direcotry
	removeCryptDir(t)
	createTestDirs(t)
	encryptDirectory(plainDir, cryptDir, true)
	checkDirTree(t, cryptDir, expectedTreeWithRoot)

	removeTestDirs(t)
}

func checkDirTree(t *testing.T, path string, expectedTree []string) {
	var rootGone bool
	var i int
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if !rootGone {
			rootGone = true
			return nil
		}
		t.Logf("current file: %v", path)
		if !strings.HasSuffix(path, expectedTree[i]) {
			t.Errorf("direcotry is not what it should be.\nexpected: %v\ngot:%v", expectedTree[i], path)
		}
		i++
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func createTestDirs(t *testing.T) {
	err := os.MkdirAll(plainDir, os.ModePerm)
	if err != nil {
		t.Errorf("failed to create test dirs\n")
	}
	err = os.MkdirAll(cryptDir, os.ModePerm)
	if err != nil {
		t.Errorf("failed to create test dirs\n")
	}
}

func removeCryptDir(t *testing.T) {
	err := os.RemoveAll(cryptDir)
	if err != nil {
		t.Error(err)
	}
}

func removeTestDirs(t *testing.T) {
	err := os.RemoveAll(testDir)
	if err != nil {
		t.Error(err)
	}
}

func doesFileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

func createFile(path string, data []byte, t *testing.T) {
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		t.Error(err)
	}
}
