package surituner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DefaultStateDir = "/var/lib/surituner/state"

type StateStore struct {
	Dir string
}

func NewStateStore(dir string) *StateStore {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultStateDir
	}
	return &StateStore{Dir: dir}
}

func (s *StateStore) Init() error {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	// Enforce restricted permissions even when directory already existed.
	if err := os.Chmod(s.Dir, 0700); err != nil {
		return fmt.Errorf("chmod state dir: %w", err)
	}
	return nil
}

func (s *StateStore) NewStatePath() string {
	ts := time.Now().UTC().Format("20060102T150405.000000000Z")
	return filepath.Join(s.Dir, ts+".json")
}

func (s *StateStore) Save(state StateFile) (string, error) {
	if err := s.Init(); err != nil {
		return "", err
	}
	path := s.NewStatePath()
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create state: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write state: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close state: %w", err)
	}
	return path, nil
}

func (s *StateStore) Update(path string, state StateFile) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".surituner-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

func (s *StateStore) Load(path string) (StateFile, error) {
	if path == "latest" || strings.TrimSpace(path) == "" {
		var err error
		path, err = s.Latest()
		if err != nil {
			return StateFile{}, err
		}
	} else {
		var err error
		path, err = s.ResolvePath(path)
		if err != nil {
			return StateFile{}, err
		}
	}
	if err := validateStateFileTrust(path); err != nil {
		return StateFile{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return StateFile{}, fmt.Errorf("read state: %w", err)
	}
	var state StateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return StateFile{}, fmt.Errorf("parse state: %w", err)
	}
	return state, nil
}

func (s *StateStore) ResolvePath(path string) (string, error) {
	if path == "latest" || strings.TrimSpace(path) == "" {
		return s.Latest()
	}
	cleanDir, err := filepath.Abs(filepath.Clean(s.Dir))
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve state path: %w", err)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("state path must be absolute or latest: %s", path)
	}
	rel, err := filepath.Rel(cleanDir, cleanPath)
	if err != nil {
		return "", fmt.Errorf("resolve state path relative to state dir: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("state path must be inside state dir %s: %s", cleanDir, cleanPath)
	}
	if filepath.Dir(cleanPath) != cleanDir {
		return "", fmt.Errorf("state path must be a direct state file in %s: %s", cleanDir, cleanPath)
	}
	if !strings.HasSuffix(filepath.Base(cleanPath), ".json") {
		return "", fmt.Errorf("state path must point to a .json state file: %s", cleanPath)
	}
	return cleanPath, nil
}

func validateStateFileTrust(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state file must not be a symlink: %s", path)
	}
	if info.IsDir() {
		return fmt.Errorf("state path is a directory: %s", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state file permissions must not be group/world accessible: %s", path)
	}
	return nil
}

func (s *StateStore) Latest() (string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return "", fmt.Errorf("read state dir: %w", err)
	}
	var jsonFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".json") {
			jsonFiles = append(jsonFiles, filepath.Join(s.Dir, name))
		}
	}
	if len(jsonFiles) == 0 {
		return "", errors.New("no state files found")
	}
	sort.Strings(jsonFiles)
	return jsonFiles[len(jsonFiles)-1], nil
}

func BuildHostFingerprint() HostFingerprint {
	host, _ := os.Hostname()
	return HostFingerprint{
		Hostname:  host,
		MachineID: readMachineID(),
		UID:       os.Geteuid(),
	}
}

func readMachineID() string {
	candidates := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}
	for _, path := range candidates {
		if raw, err := os.ReadFile(path); err == nil {
			value := strings.TrimSpace(string(raw))
			if value != "" {
				return value
			}
		}
	}
	return "unknown"
}

func ValidateHostFingerprint(expected HostFingerprint) error {
	current := BuildHostFingerprint()
	if expected.Hostname != "" && expected.Hostname != current.Hostname {
		return fmt.Errorf("hostname mismatch: state=%s current=%s", expected.Hostname, current.Hostname)
	}
	if expected.MachineID != "" && expected.MachineID != "unknown" && expected.MachineID != current.MachineID {
		return fmt.Errorf("machine-id mismatch")
	}
	return nil
}
