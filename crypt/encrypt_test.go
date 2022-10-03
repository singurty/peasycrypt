package crypt

import (
	"bytes"
	"errors"
	"io"
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
	checkErr(err)
	testDir, err = filepath.Abs("testdata")
	checkErr(err)
	plainDir, err = filepath.Abs("testdata/plain")
	checkErr(err)
	cryptDir, err = filepath.Abs("testdata/crypt")
	checkErr(err)

	// Setup cipher
	c, err = newCipher("", "")
	checkErr(err)
	os.Exit(m.Run())
}

func TestEncryptFile(t *testing.T) {
	createTestDirs(t)
	
	plainFile := filepath.Join(plainDir, "hello.txt")
	plainData := []byte("hello this is peasycrypt speaking")
	createFile(t, plainFile, plainData)

	os.Chdir(cryptDir)
	encryptFile(plainFile, false)

	// Check encrypted filename and data
	cipherFile := filepath.Join(cryptDir, "94agtmv411602npe2kug2d5kbs")
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

func TestEncryptDirectory(t *testing.T) {
	createTestDirs(t)

	err := os.MkdirAll(filepath.Join(plainDir, "/writings/nicer"), os.ModePerm)
	if err != nil {
		t.Error(err)
	}

	createFile(t, filepath.Join(plainDir, "writings/hello.txt"), []byte("hello"))
	createFile(t, filepath.Join(plainDir, "writings/hi.txt"), []byte("hi"))
	createFile(t, filepath.Join(plainDir, "writings/nicer/nicehello.txt"), []byte("nice hello"))
	createFile(t, filepath.Join(plainDir, "writings/nicer/nicehi.txt"), []byte("nice hi"))

	expectedTreeWithoutRoot := []string{
		"3bb40sjbkfh7kggkgpk3jim8ms",
		"3bb40sjbkfh7kggkgpk3jim8ms/2629j9bcs9di0fend6cr6agabc",
		"3bb40sjbkfh7kggkgpk3jim8ms/67dcveth5b7r9bjl00vdoa8pmk",
		"3bb40sjbkfh7kggkgpk3jim8ms/67dcveth5b7r9bjl00vdoa8pmk/7b8pfkgtn2o488mjhc9t8dlv60",
		"3bb40sjbkfh7kggkgpk3jim8ms/67dcveth5b7r9bjl00vdoa8pmk/ntr7fa5tteqbunsitsffq9kc9k",
		"3bb40sjbkfh7kggkgpk3jim8ms/94agtmv411602npe2kug2d5kbs",
	}
	expectedTreeWithRoot := make([]string, len(expectedTreeWithoutRoot) + 1)
	expectedTreeWithRoot[0] = "9daaitvmvl722hchljeu5msi24"
	for i, withoutRoot := range expectedTreeWithoutRoot {
		withRoot := filepath.Join(expectedTreeWithRoot[0], withoutRoot)
		expectedTreeWithRoot[i+1] = withRoot
	}

	encryptDirectory(plainDir + "/", cryptDir, true)
	checkDirTree(t, cryptDir, expectedTreeWithoutRoot)

	// Since we set deleteSrc to true, plainDir should now be empty
	empty, err := isEmpty(plainDir, t)
	if err != nil {
		t.Error(err)
	} else if !empty {
		t.Errorf("plainDir not empty when deleteSrc set to true")
	}

	// Test again without omitting the root direcotry
	removeTestDirs(t)
	createTestDirs(t)
	encryptDirectory(plainDir, cryptDir, true)
	checkDirTree(t, cryptDir, expectedTreeWithRoot)

	// Since we set deleteSrc to true and did not omit the root directory, plainDir should not exist
	exists, err := doesFileExist(plainDir)
	if err != nil {
		t.Error(err)
	} else if exists {
		t.Errorf("plainDir not deleted when deleteSrc set to true and root dir encryption not omitted")
	}

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
//		t.Logf("current entry: %v", path)
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

func isEmpty(path string, t *testing.T) (bool, error) {
	f, err := os.Open(path)
    if err != nil {
		return false, err
    }
    defer f.Close()

	_, err = f.Readdirnames(1)
    if errors.Is(err, io.EOF) {
        return true, nil
    }
    return false, err
}

func createFile(t *testing.T, path string, data []byte) {
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		t.Error(err)
	}
}
