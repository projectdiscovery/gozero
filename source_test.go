package gozero

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSourceWithFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "testsource")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // clean up

	content := []byte("temporary file's content")
	if _, err := tempFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temporary file: %v", err)
	}

	source, err := NewSourceWithFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to create new source with file: %v", err)
	}
	if source == nil {
		t.Fatal("NewSourceWithFile returned nil source")
	}
	if source.Filename != tempFile.Name() {
		t.Errorf("Expected filename to be %v, got %v", tempFile.Name(), source.Filename)
	}
	if source.File == nil {
		t.Error("Expected non-nil File in new source")
	}
	if source.Temporary {
		t.Error("Expected new source not to be temporary")
	}

	readContent, err := os.ReadFile(source.Filename)
	if err != nil {
		t.Fatalf("Failed to read from source file: %v", err)
	}
	if !bytes.Equal(content, readContent) {
		t.Errorf("Read content does not match written content")
	}

	// Clean up
	if err := source.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup new source with file: %v", err)
	}
}

func TestNewSourceWithReader(t *testing.T) {
	content := []byte("content from reader")
	buffer := bytes.NewBuffer(content)

	pattern := "testsource-*"
	tempDir := t.TempDir()

	source, err := NewSourceWithReader(buffer, pattern, tempDir)
	if err != nil {
		t.Fatalf("Failed to create new source with reader: %v", err)
	}
	defer source.Cleanup()

	if !source.Temporary {
		t.Error("Expected source to be marked as temporary")
	}

	if !strings.HasPrefix(filepath.Base(source.Filename), "testsource-") {
		t.Errorf("Expected file to have prefix 'testsource-', got %s", filepath.Base(source.Filename))
	}
	if !strings.Contains(source.Filename, tempDir) {
		t.Errorf("Expected file to be created in directory %s, got %s", tempDir, filepath.Dir(source.Filename))
	}

	readContent, err := os.ReadFile(source.Filename)
	if err != nil {
		t.Fatalf("Failed to read from source file: %v", err)
	}
	if !bytes.Equal(content, readContent) {
		t.Errorf("Read content does not match content from reader")
	}
}
