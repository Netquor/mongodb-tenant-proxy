package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile is an append-only file that rotates by size, keeping
// maxBackups older files (path.1 is the newest backup).
type RotatingFile struct {
	path       string
	maxSize    int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewRotatingFile opens (creating, 0600) path for appending. maxSize <= 0
// defaults to 100 MiB; maxBackups < 0 keeps none, 0 defaults to 5.
func NewRotatingFile(path string, maxSize int64, maxBackups int) (*RotatingFile, error) {
	if maxSize <= 0 {
		maxSize = 100 << 20
	}
	if maxBackups == 0 {
		maxBackups = 5
	}
	r := &RotatingFile{path: path, maxSize: maxSize, maxBackups: maxBackups}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	_ = r.f.Close()
	// Rotation is best effort: a missing backup is normal, and if a rename
	// fails the next open still appends to (or recreates) the live file, so
	// no event is lost; only the retention window shrinks.
	if r.maxBackups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.maxBackups))
		for i := r.maxBackups - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		_ = os.Rename(r.path, r.path+".1")
	} else {
		_ = os.Remove(r.path)
	}
	return r.open()
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
