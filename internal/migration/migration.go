// Package migration provides value-blind, reversible policy-v1 migration.
package migration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

type Mapping struct {
	Alias    string `json:"alias"`
	Entry    string `json:"entry"`
	Kind     string `json:"kind"`
	Filename string `json:"filename,omitempty"`
	Store    string `json:"store,omitempty"`
	Copied   bool   `json:"copied"`
}

type Preview struct {
	PolicyPath  string
	Environment string
	Mappings    []Mapping
}

type Manifest struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	PolicyPath  string    `json:"policy_path"`
	Environment string    `json:"environment"`
	CreatedAt   time.Time `json:"created_at"`
	Mappings    []Mapping `json:"mappings"`
}

type valueCopy struct {
	mapping Mapping
	value   []byte
}

var openEnvironment = envset.Open
var openSecretStore = secretstore.Open

func Plan(policyPath string) (Preview, error) {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		return Preview{}, err
	}
	f, err := policy.Load(abs)
	if err != nil {
		return Preview{}, err
	}
	if f.Version != policy.SupportedVersionV1 {
		return Preview{}, fmt.Errorf("policy is version %s; only version 1 needs migration", f.Version)
	}
	environment := "dev"
	if f.EnvironmentSet == "active" {
		manager, openErr := openEnvironment(filepath.Dir(abs))
		if openErr != nil {
			return Preview{}, openErr
		}
		active, activeErr := manager.Active()
		if activeErr != nil {
			return Preview{}, activeErr
		}
		environment = active.Name
	}
	mappings := make([]Mapping, 0, len(f.Secrets))
	for alias, secret := range f.Secrets {
		mappings = append(mappings, Mapping{Alias: alias, Entry: secret.Env, Kind: secret.EffectiveKind(), Filename: secret.Filename, Store: secret.Store, Copied: f.EnvironmentSet != "active"})
	}
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].Alias < mappings[j].Alias })
	return Preview{PolicyPath: abs, Environment: environment, Mappings: mappings}, nil
}

func Apply(policyPath string) (Manifest, error) {
	preview, err := Plan(policyPath)
	if err != nil {
		return Manifest{}, err
	}
	original, err := os.ReadFile(preview.PolicyPath)
	if err != nil {
		return Manifest{}, err
	}
	f, err := policy.Parse(original)
	if err != nil {
		return Manifest{}, err
	}
	migrated, _, err := policy.MigrateV1ToV2(original)
	if err != nil {
		return Manifest{}, err
	}
	root := filepath.Dir(preview.PolicyPath)
	environments, err := openEnvironment(root)
	if err != nil {
		return Manifest{}, fmt.Errorf("open encrypted environment: %w", err)
	}
	if _, ok := environments.Set(preview.Environment); !ok {
		if _, err := environments.Ensure(preview.Environment); err != nil {
			return Manifest{}, err
		}
	}

	var copies []valueCopy
	for _, item := range preview.Mappings {
		if f.EnvironmentSet == "active" {
			entry, ok := environments.Entry(preview.Environment, item.Entry)
			if !ok {
				return Manifest{}, fmt.Errorf("legacy environment entry %q is missing", item.Entry)
			}
			if entry.Kind == envset.EntryFile {
				if _, err := environments.GetBytes(preview.Environment, item.Entry); err != nil {
					return Manifest{}, fmt.Errorf("verify file entry %q: %w", item.Entry, err)
				}
			} else if _, err := environments.Get(preview.Environment, item.Entry); err != nil {
				return Manifest{}, fmt.Errorf("verify entry %q: %w", item.Entry, err)
			}
			continue
		}
		if _, exists := environments.Entry(preview.Environment, item.Entry); exists {
			return Manifest{}, fmt.Errorf("destination entry %q already exists; migration will not overwrite it", item.Entry)
		}
		store, err := openSecretStore(preview.PolicyPath, item.Store)
		if err != nil {
			return Manifest{}, fmt.Errorf("open legacy store for %q: %w", item.Alias, err)
		}
		value, err := store.Get(item.Alias)
		if err != nil {
			return Manifest{}, fmt.Errorf("legacy secret %q is unavailable", item.Alias)
		}
		copies = append(copies, valueCopy{mapping: item, value: []byte(value)})
	}

	id, err := migrationID()
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Version: 1, ID: id, Status: "prepared", PolicyPath: preview.PolicyPath, Environment: preview.Environment, CreatedAt: time.Now().UTC(), Mappings: preview.Mappings}
	dir := migrationDir(root, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Manifest{}, err
	}
	if err := writePrivate(filepath.Join(dir, "policy-v1.yml"), original); err != nil {
		return Manifest{}, err
	}
	if err := saveManifest(dir, manifest); err != nil {
		return Manifest{}, err
	}

	var added []string
	rollbackValues := func() {
		for i := len(added) - 1; i >= 0; i-- {
			_ = environments.DeleteKey(preview.Environment, added[i])
		}
	}
	for i := range copies {
		item := copies[i]
		entry := envset.Entry{Name: item.mapping.Entry, Target: item.mapping.Entry, Kind: envset.EntryKind(item.mapping.Kind), Filename: item.mapping.Filename}
		if err := environments.PutEntry(preview.Environment, entry, item.value); err != nil {
			zero(item.value)
			rollbackValues()
			return Manifest{}, fmt.Errorf("copy %q into encrypted environment: %w", item.mapping.Alias, err)
		}
		stored, verifyErr := environments.GetBytes(preview.Environment, item.mapping.Entry)
		if verifyErr != nil || string(stored) != string(item.value) {
			zero(stored)
			zero(item.value)
			rollbackValues()
			return Manifest{}, fmt.Errorf("encrypted verification failed for %q", item.mapping.Entry)
		}
		zero(stored)
		zero(item.value)
		added = append(added, item.mapping.Entry)
	}
	if err := replaceFile(preview.PolicyPath, migrated); err != nil {
		rollbackValues()
		return Manifest{}, err
	}
	if _, err := policy.Load(preview.PolicyPath); err != nil {
		_ = replaceFile(preview.PolicyPath, original)
		rollbackValues()
		return Manifest{}, fmt.Errorf("migrated policy verification failed: %w", err)
	}
	manifest.Status = "applied"
	if err := saveManifest(dir, manifest); err != nil {
		_ = replaceFile(preview.PolicyPath, original)
		rollbackValues()
		return Manifest{}, err
	}
	return manifest, nil
}

func Rollback(policyPath, id string) (Manifest, error) {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		return Manifest{}, err
	}
	dir, manifest, err := loadMigration(filepath.Dir(abs), id)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.Status != "applied" {
		return Manifest{}, fmt.Errorf("migration %s is %s and cannot be rolled back", manifest.ID, manifest.Status)
	}
	backup, err := os.ReadFile(filepath.Join(dir, "policy-v1.yml"))
	if err != nil {
		return Manifest{}, err
	}
	if err := replaceFile(abs, backup); err != nil {
		return Manifest{}, err
	}
	if _, err := policy.Load(abs); err != nil {
		return Manifest{}, fmt.Errorf("restored policy verification failed: %w", err)
	}
	environments, err := openEnvironment(filepath.Dir(abs))
	if err != nil {
		return Manifest{}, err
	}
	for _, item := range manifest.Mappings {
		if item.Copied {
			if err := environments.DeleteKey(manifest.Environment, item.Entry); err != nil && !errors.Is(err, envset.ErrMissing) {
				return Manifest{}, fmt.Errorf("remove migrated entry %q: %w", item.Entry, err)
			}
		}
	}
	manifest.Status = "rolled_back"
	return manifest, saveManifest(dir, manifest)
}

// Cleanup removes legacy provider-store aliases only after the v2 policy and
// encrypted copies have been accepted. Cleanup deliberately ends rollback.
func Cleanup(policyPath, id string) (Manifest, error) {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		return Manifest{}, err
	}
	dir, manifest, err := loadMigration(filepath.Dir(abs), id)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.Status != "applied" {
		return Manifest{}, fmt.Errorf("migration %s is %s and cannot be cleaned", manifest.ID, manifest.Status)
	}
	f, err := policy.Load(abs)
	if err != nil || !f.UsesEnvironmentEntries() {
		return Manifest{}, errors.New("current policy is not a verified version-2 policy")
	}
	for _, item := range manifest.Mappings {
		if !item.Copied {
			continue
		}
		store, err := openSecretStore(abs, item.Store)
		if err != nil {
			return Manifest{}, err
		}
		if err := store.Delete(item.Alias); err != nil {
			return Manifest{}, fmt.Errorf("delete legacy alias %q: %w", item.Alias, err)
		}
	}
	manifest.Status = "cleaned"
	return manifest, saveManifest(dir, manifest)
}

func migrationDir(root, id string) string { return filepath.Join(root, ".ironrun", "migrations", id) }

func loadMigration(root, id string) (string, Manifest, error) {
	base := filepath.Join(root, ".ironrun", "migrations")
	if id == "" {
		entries, err := os.ReadDir(base)
		if err != nil {
			return "", Manifest{}, err
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i].IsDir() {
				id = entries[i].Name()
				break
			}
		}
	}
	if id == "" || strings.ContainsAny(id, `/\\`) || filepath.Base(id) != id {
		return "", Manifest{}, errors.New("valid migration ID is required")
	}
	dir := migrationDir(root, id)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return "", Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", Manifest{}, err
	}
	if manifest.ID != id || manifest.Version != 1 {
		return "", Manifest{}, errors.New("migration manifest identity mismatch")
	}
	return dir, manifest, nil
}

func saveManifest(dir string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "manifest.json"), append(data, '\n'))
}

func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ironrun-policy-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(name, path)
}

func writePrivate(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func migrationID() (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
