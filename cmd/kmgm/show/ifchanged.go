package show

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
)

type IfChangedWriteFile struct {
	f               *os.File
	originalContent []byte
	buf             bytes.Buffer
}

var _ io.Writer = &IfChangedWriteFile{}

func NewIfChangedWriteFile(path string) (*IfChangedWriteFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		f.Close()
		return nil, err
	}
	originalContent, err := ioutil.ReadAll(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &IfChangedWriteFile{
		f:               f,
		originalContent: originalContent,
	}, nil
}

func (wf *IfChangedWriteFile) Write(bs []byte) (int, error) {
	return wf.buf.Write(bs)
}

func (wf *IfChangedWriteFile) Close() error {
	bs := wf.buf.Bytes()
	if !bytes.Equal(wf.originalContent, bs) {
		if _, err := wf.f.Seek(0, os.SEEK_SET); err != nil {
			wf.f.Close()
			return err
		}
		if _, err := wf.f.Write(bs); err != nil {
			wf.f.Close()
			return err
		}
	}

	if err := wf.f.Close(); err != nil {
		return err
	}
	return nil
}
