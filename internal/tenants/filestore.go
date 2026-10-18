package tenants

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// FileStore persists dynamic tenants and users in one JSON file, rewritten
// atomically (write temp file + rename) with mode 0600.
type FileStore struct {
	path string
	mu   sync.Mutex
}

type fileData struct {
	Tenants []Tenant `json:"tenants"`
	Users   []User   `json:"users"`
}

// NewFileStore returns a store backed by path (created on first write).
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

func (f *FileStore) read() (*fileData, error) {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return &fileData{}, nil
	}
	if err != nil {
		return nil, err
	}
	d := &fileData{}
	if len(b) == 0 {
		return d, nil
	}
	return d, json.Unmarshal(b, d)
}

func (f *FileStore) write(d *fileData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".tenants-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

func (f *FileStore) List(context.Context) ([]Tenant, []User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.read()
	if err != nil {
		return nil, nil, err
	}
	return d.Tenants, d.Users, nil
}

func (f *FileStore) update(fn func(*fileData)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.read()
	if err != nil {
		return err
	}
	fn(d)
	return f.write(d)
}

func (f *FileStore) PutTenant(_ context.Context, t Tenant) error {
	return f.update(func(d *fileData) {
		for i := range d.Tenants {
			if d.Tenants[i].ID == t.ID {
				d.Tenants[i] = t
				return
			}
		}
		d.Tenants = append(d.Tenants, t)
	})
}

func (f *FileStore) DeleteTenant(_ context.Context, id string) error {
	return f.update(func(d *fileData) {
		ts := d.Tenants[:0]
		for _, t := range d.Tenants {
			if t.ID != id {
				ts = append(ts, t)
			}
		}
		d.Tenants = ts
		us := d.Users[:0]
		for _, u := range d.Users {
			if u.TenantID != id {
				us = append(us, u)
			}
		}
		d.Users = us
	})
}

func (f *FileStore) PutUser(_ context.Context, u User) error {
	return f.update(func(d *fileData) {
		for i := range d.Users {
			if d.Users[i].Username == u.Username {
				d.Users[i] = u
				return
			}
		}
		d.Users = append(d.Users, u)
	})
}

func (f *FileStore) DeleteUser(_ context.Context, username string) error {
	return f.update(func(d *fileData) {
		us := d.Users[:0]
		for _, u := range d.Users {
			if u.Username != username {
				us = append(us, u)
			}
		}
		d.Users = us
	})
}

func (f *FileStore) Close() error { return nil }
