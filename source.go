package gozero

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
)

type Source struct {
	Temporary       bool
	CloseAfterWrite bool
	Filename        string
	File            *os.File
}

func NewSource() (*Source, error) {
	return NewSourceWithString("")
}

func NewSourceWithFile(src string) (*Source, error) {
	if fileutil.FileExists(src) {
		file, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		return &Source{Filename: src, File: file}, nil
	}
	return nil, errors.New("file does not exist")
}

func NewSourceWithBytes(src []byte) (*Source, error) {
	return NewSourceWithReader(bytes.NewReader(src))
}

func NewSourceWithString(src string) (*Source, error) {
	return NewSourceWithReader(strings.NewReader(src))
}

func NewSourceWithReader(src io.Reader) (*Source, error) {
	srcFile, err := os.CreateTemp("", "")
	if err != nil {
		return nil, err
	}

	gfileName := srcFile.Name()
	if _, err := io.Copy(srcFile, src); err != nil {
		return nil, err
	}

	if err := srcFile.Sync(); err != nil {
		return nil, err
	}

	if _, err := srcFile.Seek(0, 0); err != nil {
		return nil, err
	}

	return &Source{Filename: gfileName, Temporary: true, File: srcFile}, nil
}

func (s *Source) Close() error {
	if s.File != nil {
		return s.File.Close()
	}

	return nil
}

func (s *Source) Cleanup() error {
	if err := s.Close(); err != nil {
		return err
	}

	if s.Temporary {
		return os.RemoveAll(s.Filename)
	}

	return errors.New("no cleanup needed")
}

func (s *Source) ReadAll() ([]byte, error) {
	return os.ReadFile(s.Filename)
}
