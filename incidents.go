package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Incident types
// ---------------------------------------------------------------------------

// Incident represents a flagged event sequence requiring investigation.
type Incident struct {
	ID        string   `json:"id"`
	SessionID string   `json:"session_id"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"` // info, warning, alert, critical
	Status    string   `json:"status"`   // open, investigating, resolved, closed
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	EventIDs  []string `json:"event_ids,omitempty"` // specific events, or empty = all session events
}

// TimelineEntry is a human-readable view of an event within an incident.
type TimelineEntry struct {
	RelativeMs int64  `json:"relative_ms"`
	Timestamp  string `json:"timestamp"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	EventID    string `json:"event_id"`
}

// CaseBundle is a signed, exportable evidence package.
type CaseBundle struct {
	Version         string          `json:"version"`
	IncidentID      string          `json:"incident_id"`
	Title           string          `json:"title"`
	CreatedAt       string          `json:"created_at"`
	Hostname        string          `json:"hostname"`
	Incident        Incident        `json:"incident"`
	Events          []Event         `json:"events"`
	Timeline        []TimelineEntry `json:"timeline"`
	Redaction       RedactionStats  `json:"redaction"`
	Integrity       string          `json:"integrity"`        // SHA-256 of event hashes
	SourceIntegrity string          `json:"source_integrity"` // SHA-256 of original stored hashes
	Signature       string          `json:"signature,omitempty"`
	PublicKey       string          `json:"public_key,omitempty"`
	SignedAt        string          `json:"signed_at,omitempty"`
}

// PrivacyProfileConfig controls what gets redacted in case bundles.
type PrivacyProfileConfig struct {
	Redact        bool     `yaml:"redact"`
	StripHostname bool     `yaml:"strip_hostname"`
	Patterns      []string `yaml:"patterns"`
}

// ---------------------------------------------------------------------------
// Timeline builder
// ---------------------------------------------------------------------------

// BuildTimeline creates a chronological timeline from events.
func BuildTimeline(events []Event) []TimelineEntry {
	if len(events) == 0 {
		return nil
	}

	// Sort by timestamp.
	sorted := make([]Event, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp < sorted[j].Timestamp
	})

	// Parse first event time for relative calculation.
	firstTime, _ := time.Parse(time.RFC3339Nano, sorted[0].Timestamp)

	entries := make([]TimelineEntry, len(sorted))
	for i, e := range sorted {
		eventTime, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		entries[i] = TimelineEntry{
			RelativeMs: eventTime.Sub(firstTime).Milliseconds(),
			Timestamp:  e.Timestamp,
			Source:     e.Source,
			Type:       e.Type,
			Severity:   e.Severity,
			Summary:    summarizeEvent(e),
			EventID:    e.ID,
		}
	}
	return entries
}

func SelectIncidentEvents(inc *Incident, events []Event) ([]Event, error) {
	if inc == nil || len(inc.EventIDs) == 0 {
		return events, nil
	}
	wanted := make(map[string]bool, len(inc.EventIDs))
	for _, id := range inc.EventIDs {
		wanted[id] = true
	}
	selected := make([]Event, 0, len(wanted))
	for _, event := range events {
		if wanted[event.ID] {
			selected = append(selected, event)
			delete(wanted, event.ID)
		}
	}
	if len(wanted) != 0 {
		return nil, fmt.Errorf("incident references missing events")
	}
	return selected, nil
}

// ---------------------------------------------------------------------------
// Incident store (file-backed with fsync)
// ---------------------------------------------------------------------------

// IncidentStore manages incident persistence.
type IncidentStore struct {
	mu        sync.RWMutex
	incidents map[string]*Incident
	dataDir   string
}

var readIncidentDirectory = os.ReadDir

// NewIncidentStore creates or loads an incident store.
func NewIncidentStore(dataDir string) (*IncidentStore, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, fmt.Errorf("data directory must be canonical and absolute")
	}
	dir := filepath.Join(dataDir, "incidents")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create incidents dir: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !trustedFileOwner(info) {
		return nil, fmt.Errorf("incidents directory is not a safe directory")
	}

	store := &IncidentStore{
		incidents: make(map[string]*Incident),
		dataDir:   dir,
	}

	// Existing case metadata is evidence: corruption and unsafe entries prevent
	// startup instead of being silently hidden.
	entries, err := readIncidentDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("read incidents directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
			return nil, fmt.Errorf("incident %s has unsafe permissions or ownership", entry.Name())
		}
		data, err := readBoundedRegularFile(path, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read incident %s: %w", entry.Name(), err)
		}
		var inc Incident
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inc); err != nil {
			return nil, fmt.Errorf("decode incident %s: %w", entry.Name(), err)
		}
		if err := ensureJSONDecoderEOF(decoder); err != nil {
			return nil, fmt.Errorf("decode incident %s: %w", entry.Name(), err)
		}
		if !validObjectID(inc.ID) || strings.TrimSuffix(entry.Name(), ".json") != inc.ID {
			return nil, fmt.Errorf("incident %s has invalid identity binding", entry.Name())
		}
		if err := validateIncident(inc); err != nil {
			return nil, fmt.Errorf("incident %s is invalid: %w", entry.Name(), err)
		}
		copy := cloneIncident(inc)
		store.incidents[inc.ID] = &copy
	}
	return store, nil
}

// Create adds a new incident with fsync.
func (s *IncidentStore) Create(inc Incident) (*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if inc.ID == "" {
		inc.ID = generateID()
	}
	if !validObjectID(inc.ID) {
		return nil, fmt.Errorf("invalid incident id")
	}
	if _, exists := s.incidents[inc.ID]; exists {
		return nil, fmt.Errorf("incident already exists")
	}
	if inc.CreatedAt == "" {
		inc.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if inc.Status == "" {
		inc.Status = "open"
	}
	if inc.Severity == "" {
		inc.Severity = "alert"
	}
	if err := validateIncident(inc); err != nil {
		return nil, err
	}

	// Persist with fsync.
	data, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal incident: %w", err)
	}
	path := filepath.Join(s.dataDir, inc.ID+".json")
	if err := writeFileSync(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write incident: %w", err)
	}

	stored := cloneIncident(inc)
	s.incidents[inc.ID] = &stored
	result := cloneIncident(stored)
	return &result, nil
}

// Get returns an incident by ID.
func (s *IncidentStore) Get(id string) (*Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	if !ok {
		return nil, false
	}
	copy := cloneIncident(*inc)
	return &copy, true
}

// List returns all incidents, newest first.
func (s *IncidentStore) List() []*Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Incident
	for _, inc := range s.incidents {
		copy := cloneIncident(*inc)
		result = append(result, &copy)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})
	return result
}

// Update persists changes to an existing incident with fsync.
func (s *IncidentStore) Update(inc *Incident) error {
	if inc == nil || !validObjectID(inc.ID) {
		return fmt.Errorf("invalid incident")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.incidents[inc.ID]; !exists {
		return fmt.Errorf("incident does not exist")
	}

	updated := cloneIncident(*inc)
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := validateIncident(updated); err != nil {
		return err
	}

	data, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}
	path := filepath.Join(s.dataDir, updated.ID+".json")
	if err := writeFileSync(path, data, 0600); err != nil {
		return fmt.Errorf("write incident: %w", err)
	}

	s.incidents[updated.ID] = &updated
	return nil
}

func validObjectID(value string) bool {
	if value == "" || len(value) > 128 || filepath.Base(value) != value {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return value != "." && value != ".."
}

func cloneIncident(inc Incident) Incident {
	inc.Tags = append([]string(nil), inc.Tags...)
	inc.EventIDs = append([]string(nil), inc.EventIDs...)
	return inc
}

// writeFileSync writes data to a file and fsyncs before closing.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".incident-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	cleanup := func() { f.Close(); os.Remove(tmpPath) }
	if err := f.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// #nosec G304 -- dir is the trusted store/output parent and this handle is used only to fsync an atomic rename.
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	// #nosec G703 -- this helper accepts an explicit local path and rejects links, non-regular files, oversize files, and opened-file identity changes.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > limit {
		return nil, fmt.Errorf("not a bounded regular file")
	}
	// #nosec G304,G703 -- path was Lstat-validated as a bounded regular non-symlink and is identity-checked after open.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds limit or could not be read")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("file changed while reading")
	}
	return data, nil
}

func readOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	// #nosec G703 -- callers provide a local key/token path whose type, owner, mode, bounds, and identity are checked before and after the read.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 || !trustedFileOwner(before) {
		return nil, fmt.Errorf("file must be regular and owner-only")
	}
	data, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- post-read identity, ownership, and permission validation closes the trust check.
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0o077 != 0 || !trustedFileOwner(after) {
		return nil, fmt.Errorf("file changed while validating permissions")
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// Case bundle packaging
// ---------------------------------------------------------------------------

// computeIntegrity computes a SHA-256 digest over all event hashes.
func computeIntegrity(events []Event) string {
	h := sha256.New()
	for _, e := range events {
		h.Write([]byte(e.Hash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func rechainEvents(events []Event) ([]Event, error) {
	result := make([]Event, len(events))
	previous := ""
	for i, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("copy event: %w", err)
		}
		if err := json.Unmarshal(data, &result[i]); err != nil {
			return nil, fmt.Errorf("copy event: %w", err)
		}
		result[i].PrevHash = previous
		result[i].Hash = computeEventHash(result[i])
		previous = result[i].Hash
	}
	return result, nil
}

// PackageBundle creates a signed, redacted case bundle for an incident.
// The privacy profile controls what gets redacted and whether hostname is stripped.
func PackageBundle(inc *Incident, events []Event, profile PrivacyProfileConfig, keyPath string) (*CaseBundle, error) {
	// Apply redaction to a copy of events.
	var bundleEvents []Event
	stats := RedactionStats{Counts: make(map[string]int)}
	bundleIncident := cloneIncident(*inc)
	if profile.Redact {
		rules := enabledRedactionRules(profile.Patterns)
		bundleEvents = redactEventsWithRules(events, rules, &stats)
		bundleIncident = RedactIncident(bundleIncident, rules, &stats)
	} else {
		bundleEvents = make([]Event, len(events))
		copy(bundleEvents, events)
	}
	var err error
	bundleEvents, err = rechainEvents(bundleEvents)
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()
	if profile.StripHostname {
		hostname = "[REDACTED]"
	}

	bundle := &CaseBundle{
		Version:         "1",
		IncidentID:      inc.ID,
		Title:           bundleIncident.Title,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		Hostname:        hostname,
		Incident:        bundleIncident,
		Events:          bundleEvents,
		Timeline:        BuildTimeline(bundleEvents),
		Redaction:       stats,
		Integrity:       computeIntegrity(bundleEvents),
		SourceIntegrity: computeIntegrity(events),
	}

	// Sign if key is available.
	if keyPath != "" {
		if err := signBundle(bundle, keyPath); err != nil {
			return bundle, fmt.Errorf("sign bundle: %w", err)
		}
	}

	return bundle, nil
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification
// ---------------------------------------------------------------------------

// signableBundlePayload returns the canonical bytes for signing a bundle.
func signableBundlePayload(bundle CaseBundle) ([]byte, error) {
	clean := bundle
	clean.Signature = ""
	return json.Marshal(clean)
}

func signBundle(bundle *CaseBundle, keyPath string) error {
	keyData, err := readOwnerOnlyFile(keyPath, 4096)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return fmt.Errorf("decode signing key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	bundle.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	bundle.SignedAt = time.Now().UTC().Format(time.RFC3339Nano)
	payload, err := signableBundlePayload(*bundle)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)
	bundle.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyBundle checks integrity and signature of a case bundle.
func VerifyBundle(bundle *CaseBundle, pubKeyPath string) error {
	if bundle == nil || bundle.Version != "1" || !validObjectID(bundle.IncidentID) ||
		bundle.Incident.ID != bundle.IncidentID {
		return fmt.Errorf("invalid bundle identity or version")
	}
	if len(bundle.Events) > 100000 {
		return fmt.Errorf("bundle contains too many events")
	}
	// Verify event hash chain.
	if err := verifyEventChain(bundle.Events); err != nil {
		return fmt.Errorf("event chain: %w", err)
	}
	if bundle.Integrity != computeIntegrity(bundle.Events) {
		return fmt.Errorf("bundle integrity digest mismatch")
	}

	// Verification is an authenticity claim, so unsigned bundles and embedded
	// self-selected keys are never accepted as trusted evidence.
	if bundle.Signature == "" {
		return fmt.Errorf("bundle is unsigned")
	}
	if pubKeyPath == "" {
		return fmt.Errorf("trusted public key path is required; embedded keys are not trust anchors")
	}
	data, err := readBoundedRegularFile(pubKeyPath, 4096)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubBytes, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if decErr != nil {
		return fmt.Errorf("decode public key file: %w", decErr)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	if bundle.PublicKey != "" && bundle.PublicKey != base64.StdEncoding.EncodeToString(pubBytes) {
		return fmt.Errorf("embedded public key does not match trusted public key")
	}
	if _, err := time.Parse(time.RFC3339Nano, bundle.SignedAt); err != nil {
		return fmt.Errorf("invalid signed_at timestamp")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	payload, err := signableBundlePayload(*bundle)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		return fmt.Errorf("signature verification FAILED — bundle may have been tampered with")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Key generation (same as runtime-attestor)
// ---------------------------------------------------------------------------

func generateKeypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if err := writeNewKeyFile(privPath, []byte(privB64), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeNewKeyFile(pubPath, []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("write public key: %w (private key was created and must be secured)", err)
	}
	return nil
}

func writeNewKeyFile(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- path is an explicit local CLI output; O_EXCL prevents overwriting an existing key file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
