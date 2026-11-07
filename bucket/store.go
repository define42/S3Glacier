// Package bucket persists immutable archive bucket configurations.
package bucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const (
	DefaultName            = "data"
	DefaultTarFilesPerHour = 256
	MaxTarFilesPerHour     = 65536

	configVersion = 1
	bucketLayout  = "bucket"
)

var (
	ErrNotFound        = errors.New("bucket: not found")
	ErrInvalidName     = errors.New("bucket: invalid name")
	ErrInvalidTarFiles = errors.New("bucket: invalid tar files per hour")
	ErrExists          = errors.New("bucket: already exists")

	validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

// Bucket describes a bucket's immutable storage layout.
type Bucket struct {
	Name            string    `json:"name"`
	TarFilesPerHour int       `json:"tar_files_per_hour"`
	CreatedAt       time.Time `json:"created_at"`
	Path            string    `json:"-"`
}

// Store manages bucket configurations under a single absolute data root.
type Store struct {
	root    string
	metaDir string
	mu      sync.RWMutex
	buckets map[string]Bucket
}

type diskConfig struct {
	Version         int       `json:"version"`
	Layout          string    `json:"layout"`
	Name            string    `json:"name"`
	TarFilesPerHour int       `json:"tar_files_per_hour"`
	CreatedAt       time.Time `json:"created_at"`
}

// Open loads persisted buckets and creates the default data bucket if absent.
// Invalid persisted configurations prevent the store from opening.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("bucket: data root is empty")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("bucket: resolve data root: %w", err)
	}
	s := &Store{root: absRoot, metaDir: filepath.Join(absRoot, ".buckets")}
	if err := os.MkdirAll(s.metaDir, 0700); err != nil {
		return nil, fmt.Errorf("bucket: create configuration directory: %w", err)
	}
	if err := syncDirectory(s.root); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(s.metaDir, ".lock"))
	if err := lock.Lock(); err != nil {
		return nil, fmt.Errorf("bucket: lock configurations: %w", err)
	}
	defer lock.Unlock()

	s.buckets, err = s.load()
	if err != nil {
		return nil, err
	}
	if _, ok := s.buckets[DefaultName]; !ok {
		if _, err := s.create(DefaultName, DefaultTarFilesPerHour); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Create durably publishes a new bucket. Existing buckets can never be changed,
// including by calling Create again with the same configuration.
func (s *Store) Create(name string, count int) (Bucket, error) {
	if err := validateName(name); err != nil {
		return Bucket{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock := flock.New(filepath.Join(s.metaDir, ".lock"))
	if err := lock.Lock(); err != nil {
		return Bucket{}, fmt.Errorf("bucket: lock configurations: %w", err)
	}
	defer lock.Unlock()

	// Reload under the filesystem lock so independent Store instances cannot
	// create the same name or overwrite a configuration created by another.
	buckets, err := s.load()
	if err != nil {
		return Bucket{}, err
	}
	for existingName, existing := range s.buckets {
		loaded, ok := buckets[existingName]
		if !ok || loaded.Name != existing.Name || loaded.TarFilesPerHour != existing.TarFilesPerHour ||
			loaded.Path != existing.Path || !loaded.CreatedAt.Equal(existing.CreatedAt) {
			return Bucket{}, fmt.Errorf("bucket: immutable configuration %q was changed or removed", existingName)
		}
	}
	s.buckets = buckets
	if _, ok := s.buckets[name]; ok {
		return Bucket{}, fmt.Errorf("%w: %s", ErrExists, name)
	}
	if err := validateCount(count); err != nil {
		return Bucket{}, err
	}
	return s.create(name, count)
}

// create is called with the configuration lock held and publishes the bucket
// only after its data directory and configuration are durable.
func (s *Store) create(name string, count int) (Bucket, error) {
	b := Bucket{
		Name: name, TarFilesPerHour: count, CreatedAt: time.Now().UTC(),
		Path: filepath.Join(s.root, "buckets", name),
	}
	if err := os.MkdirAll(b.Path, 0700); err != nil {
		return Bucket{}, fmt.Errorf("bucket: create data directory: %w", err)
	}
	if err := syncDirectory(filepath.Dir(b.Path)); err != nil {
		return Bucket{}, err
	}
	if err := syncDirectory(s.root); err != nil {
		return Bucket{}, err
	}
	if err := s.publish(b); err != nil {
		return Bucket{}, err
	}
	s.buckets[name] = b
	return b, nil
}

// Get returns a copy of the named bucket configuration.
func (s *Store) Get(name string) (Bucket, error) {
	if err := validateName(name); err != nil {
		return Bucket{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.buckets[name]
	if !ok {
		return Bucket{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return b, nil
}

// List returns independent copies of the buckets, sorted by name.
func (s *Store) List() []Bucket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	buckets := make([]Bucket, 0, len(s.buckets))
	for _, b := range s.buckets {
		buckets = append(buckets, b)
	}
	slices.SortFunc(buckets, func(a, b Bucket) int { return strings.Compare(a.Name, b.Name) })
	return buckets
}

func validateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("%w: use 3-63 lowercase letters, digits or hyphens with alphanumeric ends", ErrInvalidName)
	}
	switch name {
	case "buckets", "files", "static", "get", "rawupload", "upload", "uuid", "uuidv1", "redirect", "metrics", "api":
		return fmt.Errorf("%w: %q is reserved", ErrInvalidName, name)
	}
	return nil
}

func validateCount(count int) error {
	if count < 1 || count > MaxTarFilesPerHour {
		return fmt.Errorf("%w: must be between 1 and %d", ErrInvalidTarFiles, MaxTarFilesPerHour)
	}
	return nil
}

func (s *Store) load() (map[string]Bucket, error) {
	entries, err := os.ReadDir(s.metaDir)
	if err != nil {
		return nil, fmt.Errorf("bucket: read configurations: %w", err)
	}
	buckets := make(map[string]Bucket)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("bucket: configuration %q is not a regular file", entry.Name())
		}
		b, err := s.readConfig(filepath.Join(s.metaDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("bucket: invalid configuration %q: %w", entry.Name(), err)
		}
		if entry.Name() != b.Name+".json" {
			return nil, fmt.Errorf("bucket: configuration name does not match filename %q", entry.Name())
		}
		buckets[b.Name] = b
	}
	return buckets, nil
}

func (s *Store) readConfig(path string) (Bucket, error) {
	f, err := os.Open(path)
	if err != nil {
		return Bucket{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Bucket{}, err
	}
	if info.Size() > 64<<10 {
		return Bucket{}, errors.New("configuration exceeds 64 kib")
	}
	var cfg diskConfig
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Bucket{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Bucket{}, errors.New("expected one configuration object")
	}
	if cfg.Version != configVersion {
		return Bucket{}, fmt.Errorf("unsupported version %d", cfg.Version)
	}
	if err := validateName(cfg.Name); err != nil {
		return Bucket{}, err
	}
	if err := validateCount(cfg.TarFilesPerHour); err != nil {
		return Bucket{}, err
	}
	if cfg.CreatedAt.IsZero() {
		return Bucket{}, errors.New("creation time is missing")
	}
	if cfg.Layout != bucketLayout {
		return Bucket{}, fmt.Errorf("unsupported layout %q", cfg.Layout)
	}
	if cfg.Name == DefaultName && cfg.TarFilesPerHour != DefaultTarFilesPerHour {
		return Bucket{}, errors.New("default bucket must use 256 tar files per hour")
	}
	return Bucket{
		Name: cfg.Name, TarFilesPerHour: cfg.TarFilesPerHour,
		CreatedAt: cfg.CreatedAt, Path: filepath.Join(s.root, "buckets", cfg.Name),
	}, nil
}

func (s *Store) publish(b Bucket) error {
	cfg := diskConfig{
		Version: configVersion, Layout: bucketLayout, Name: b.Name,
		TarFilesPerHour: b.TarFilesPerHour, CreatedAt: b.CreatedAt,
	}
	f, err := os.CreateTemp(s.metaDir, ".tmp-")
	if err != nil {
		return fmt.Errorf("bucket: create temporary configuration: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		return fmt.Errorf("bucket: encode configuration: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("bucket: sync configuration: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("bucket: close configuration: %w", err)
	}
	// Link publishes the complete, synced file without ever replacing an
	// existing name, even if a writer does not honor the configuration lock.
	if err := os.Link(f.Name(), filepath.Join(s.metaDir, b.Name+".json")); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, b.Name)
		}
		return fmt.Errorf("bucket: publish configuration: %w", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		return fmt.Errorf("bucket: remove temporary configuration: %w", err)
	}
	return syncDirectory(s.metaDir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("bucket: open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("bucket: sync directory: %w", err)
	}
	return nil
}
