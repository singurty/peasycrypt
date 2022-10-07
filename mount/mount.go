package mount

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/singurty/peasycrypt/crypt"
)

var c *crypt.Cipher
var rootPath string

func Mount(path, mountpoint, password string) {
	if password == "" {
		fmt.Printf("Enter password: ")
		passwordByte, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		password = string(passwordByte)
		if err != nil {
			panic(err)
		}
	}
	fmt.Print("\n")
	rootPath = path
	var err error
	c, err = crypt.NewCipher(string(password), "")
	if err != nil {
		panic(err)
	}

	conn, err := fuse.Mount(mountpoint, fuse.FSName("peasycrypt"), fuse.Subtype("peasycrypt"))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Unmount and exit when interrupted
	interruptChan := make(chan os.Signal)
	signal.Notify(interruptChan, os.Interrupt)
	go func() {
		<-interruptChan
		err := fuse.Unmount(mountpoint)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()

	filesys := &FS{
		cipher: c,
	}
	err = fs.Serve(conn, filesys)
	if err != nil {
		panic(err)
	}
}

type FS struct {
	cipher *crypt.Cipher
}

func (f *FS) Root() (fs.Node, error) {
	cryptDir, err := c.NewDir(rootPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}
	n := &Dir{
		info:     info,
		path:     rootPath,
		cryptDir: cryptDir,
	}
	return n, nil
}

type Dir struct {
	info     os.FileInfo
	path     string
	cryptDir *crypt.Dir
}

var _ fs.Node = (*Dir)(nil)

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Size = uint64(d.info.Size())
	a.Mode = d.info.Mode()
	a.Mtime = d.info.ModTime()
	return nil
}

var _ = fs.HandleReadDirAller(&Dir{})

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	names, dirs, err := d.cryptDir.ReadDir()
	if err != nil {
		return nil, err
	}
	dirents := make([]fuse.Dirent, len(names))
	for i, name := range names {
		//		log.Printf("encry: %v", name)
		dirents[i].Name = name
		if dirs[i] {
			dirents[i].Type = fuse.DT_Dir
		}
	}
	return dirents, nil
}

var _ = fs.NodeRequestLookuper(&Dir{})

func (d *Dir) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fs.Node, error) {
	//	log.Printf("got lookup request: %v", req.Name)
	cryptNode, info, err := d.cryptDir.Lookup(req.Name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return &Dir{
			info:     info,
			path:     filepath.Join(d.path, req.Name),
			cryptDir: cryptNode.(*crypt.Dir),
		}, nil
	} else {
		return &File{
			info:      info,
			path:      filepath.Join(d.path, req.Name),
			cryptFile: cryptNode.(*crypt.File),
		}, nil
	}
}

type File struct {
	info      os.FileInfo
	path      string
	cryptFile *crypt.File
}

var _ fs.Node = (*File)(nil)

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Size = uint64(f.cryptFile.Size)
	a.Mode = f.info.Mode()
	a.Mtime = f.info.ModTime()
	return nil
}

var _ = fs.NodeOpener(&File{})

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle, error) {
	// Disable seeking for now. Will implement later.
	resp.Flags |= fuse.OpenNonSeekable
	r, err := f.cryptFile.NewReader()
	if err != nil {
		return nil, err
	}
	return &FileHandle{r: r}, nil
}

type FileHandle struct {
	r io.ReadCloser
}

var _ fs.Handle = (*FileHandle)(nil)

var _ fs.HandleReleaser = (*FileHandle)(nil)

func (fh *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	return fh.r.Close()
}

var _ = fs.HandleReader(&FileHandle{})

func (fh *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	buf := make([]byte, req.Size)
	n, err := io.ReadFull(fh.r, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		err = nil
	}
	resp.Data = buf[:n]
	if err != nil {
		log.Fatal(err)
	}
	return err
}
