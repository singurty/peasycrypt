package crypt

import (
	"io"
	_ "log"
	"os"
	"path/filepath"
)

type Node interface {
}

type Dir struct {
	cipher   *Cipher
	name     string
	realpath string
}

func (c *Cipher) NewDir(path string) (*Dir, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return &Dir{
		cipher:   c,
		name:     filepath.Base(path),
		realpath: path,
	}, nil
}

func (d *Dir) ReadDir() ([]string, []bool, error) {
	entries, err := os.ReadDir(d.realpath)
	if err != nil {
		return nil, nil, err
	}
	//	log.Printf("total entries: %v at %v", len(entries), d.realpath)
	names := make([]string, len(entries))
	dirs := make([]bool, len(entries))
	for i, entry := range entries {
		plainName, err := d.cipher.decryptName(entry.Name())
		if err != nil {
			return nil, nil, err
		}
		//		log.Printf("%vnth entry for %v", i, plainName)
		names[i] = plainName
		dirs[i] = entry.IsDir()
	}
	return names, dirs, nil
}

func (d *Dir) Lookup(name string) (Node, os.FileInfo, error) {
	ciphername := d.cipher.encryptName(name)
	info, err := os.Stat(filepath.Join(d.realpath, ciphername))
	if err != nil {
		return nil, nil, err
	}
	if info.IsDir() {
		return &Dir{
			cipher:   d.cipher,
			name:     name,
			realpath: filepath.Join(d.realpath, ciphername),
		}, info, nil
	} else {
		return &File{
			cipher:   d.cipher,
			name:     name,
			realpath: filepath.Join(d.realpath, ciphername),
			parent:   d,
			Size:     decryptedSize(info.Size()),
		}, info, nil
	}
}

type File struct {
	cipher   *Cipher
	name     string
	realpath string
	Size     int64 // Size of the file when unencrypted
	parent   *Dir
}

func (f *File) NewReader() (*Reader, error) {
	data, err := os.ReadFile(f.realpath)
	if err != nil {
		return nil, err
	}
	return &Reader{
		cipher: f.cipher,
		data:   data,
	}, nil
}

type Reader struct {
	cipher *Cipher
	data   []byte
}

func (r *Reader) Read(p []byte) (n int, err error) {
	decryptedData, err := r.cipher.decryptData(r.data)
	//	log.Printf("decrypted data: %s", decryptedData)
	n = copy(p, decryptedData)
	//	log.Printf("asked to read: %v actually read: %v total data: %v", len(p), n, len(r.data))
	return n, io.EOF
}

func (r *Reader) Close() error {
	return nil
}
