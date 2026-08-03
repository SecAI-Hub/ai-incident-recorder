package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
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

const (
	maxStoredEventLine = 1 << 20
	maxEventStoreSize  = 1 << 30
)

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

// Event is a single timestamped occurrence in the system.
// Events are chained via Hash/PrevHash for tamper-evident storage.
type Event struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	SessionID string                 `json:"session_id"`
	Source    string                 `json:"source"`              // originating service
	Type      string                 `json:"type"`                // event classification
	Severity  string                 `json:"severity"`            // info, warning, alert, critical
	Actor     string                 `json:"actor,omitempty"`     // who/what triggered
	Data      map[string]interface{} `json:"data,omitempty"`      // event-specific payload
	Hash      string                 `json:"hash"`                // SHA-256 of canonical event
	PrevHash  string                 `json:"prev_hash,omitempty"` // previous event hash (chain)
}

// SessionSummary describes a recording session.
type SessionSummary struct {
	SessionID  string   `json:"session_id"`
	EventCount int      `json:"event_count"`
	FirstEvent string   `json:"first_event"`
	LastEvent  string   `json:"last_event"`
	Sources    []string `json:"sources"`
}

// EventFilter specifies query criteria.
type EventFilter struct {
	SessionID string
	Source    string
	Type      string
	Severity  string
	After     string // RFC3339 timestamp
	Before    string // RFC3339 timestamp
	Limit     int
}

// ---------------------------------------------------------------------------
// Event ID generation
// ---------------------------------------------------------------------------

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

// ---------------------------------------------------------------------------
// Event hash chain
// ---------------------------------------------------------------------------

// computeEventHash returns the SHA-256 hex digest of the canonical event.
// All fields except Hash are included; PrevHash IS included to link the chain.
func computeEventHash(e Event) string {
	canonical := struct {
		ID        string                 `json:"id"`
		Timestamp string                 `json:"timestamp"`
		SessionID string                 `json:"session_id"`
		Source    string                 `json:"source"`
		Type      string                 `json:"type"`
		Severity  string                 `json:"severity"`
		Actor     string                 `json:"actor,omitempty"`
		Data      map[string]interface{} `json:"data,omitempty"`
		PrevHash  string                 `json:"prev_hash,omitempty"`
	}{
		ID:        e.ID,
		Timestamp: e.Timestamp,
		SessionID: e.SessionID,
		Source:    e.Source,
		Type:      e.Type,
		Severity:  e.Severity,
		Actor:     e.Actor,
		Data:      e.Data,
		PrevHash:  e.PrevHash,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// verifyEventChain checks the integrity of an ordered event sequence.
func verifyEventChain(events []Event) error {
	for i, e := range events {
		// Verify prev_hash linkage.
		if i == 0 {
			if e.PrevHash != "" {
				// First event may have a prev_hash from a prior session; skip linkage check.
			}
		} else {
			if e.PrevHash != events[i-1].Hash {
				return fmt.Errorf("chain broken at event %d (%s): prev_hash mismatch", i, e.ID)
			}
		}

		// Verify the event's own hash.
		expected := computeEventHash(e)
		if e.Hash != expected {
			return fmt.Errorf("hash mismatch at event %d (%s): expected %s, got %s", i, e.ID, expected, e.Hash)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Event store (JSONL file-backed, in-memory indexed)
// ---------------------------------------------------------------------------

// EventStore manages event persistence and querying.
type EventStore struct {
	mu        sync.RWMutex
	events    []Event
	sessions  map[string][]int // session_id -> event indices
	eventIDs  map[string]bool
	filePath  string
	file      *os.File
	lastHash  string
	retention RetentionConfig
	poisoned  error
}

// NewEventStore creates or opens an event store at the given data directory.
func NewEventStore(dataDir string, retention RetentionConfig) (*EventStore, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, fmt.Errorf("data directory must be canonical and absolute")
	}
	eventsDir := dataDir
	if err := os.MkdirAll(eventsDir, 0700); err != nil {
		return nil, fmt.Errorf("create events dir: %w", err)
	}
	if info, err := os.Lstat(eventsDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !trustedFileOwner(info) {
		return nil, fmt.Errorf("events directory is not a safe directory")
	}

	filePath := filepath.Join(eventsDir, "events.jsonl")

	store := &EventStore{
		sessions:  make(map[string][]int),
		eventIDs:  make(map[string]bool),
		filePath:  filePath,
		retention: retention,
	}

	// Existing evidence is fail-closed: a malformed line, a broken hash chain,
	// or an unsafe backing file prevents the recorder from accepting new data.
	if err := store.loadExisting(); err != nil {
		return nil, err
	}

	// Purge expired events before opening for writes.
	if retention.ExpireAfterDays > 0 {
		if err := store.purgeExpired(); err != nil {
			return nil, fmt.Errorf("purge expired events: %w", err)
		}
	}

	// Open file for appending unless retention already atomically replaced and
	// reopened it.
	if store.file == nil {
		f, err := openEventAppend(filePath)
		if err != nil {
			return nil, fmt.Errorf("open events file: %w", err)
		}
		store.file = f
	}

	return store, nil
}

func openEventAppend(path string) (*os.File, error) {
	// #nosec G304 -- callers derive this from a canonical trusted data/audit directory and the opened inode is revalidated below.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	pathInfo, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) ||
		opened.Mode().Perm()&0o077 != 0 || !trustedFileOwner(opened) {
		f.Close()
		return nil, fmt.Errorf("event store path is unsafe or changed while opening")
	}
	return f, nil
}

func (s *EventStore) loadExisting() error {
	info, err := os.Lstat(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat event store: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxEventStoreSize ||
		info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
		return fmt.Errorf("event store is not a bounded regular file")
	}
	f, err := os.Open(s.filePath)
	if err != nil {
		return fmt.Errorf("open event store: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return fmt.Errorf("event store changed while opening")
	}
	scanner := bufio.NewScanner(io.LimitReader(f, maxEventStoreSize+1))
	scanner.Buffer(make([]byte, 64*1024), maxStoredEventLine)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var event Event
		decoder := json.NewDecoder(strings.NewReader(string(line)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return fmt.Errorf("decode event line %d: %w", lineNumber, err)
		}
		if err := ensureJSONDecoderEOF(decoder); err != nil {
			return fmt.Errorf("decode event line %d: %w", lineNumber, err)
		}
		if err := validateEvent(event); err != nil {
			return fmt.Errorf("invalid stored event at line %d: %w", lineNumber, err)
		}
		if !validObjectID(event.ID) || s.eventIDs[event.ID] {
			return fmt.Errorf("duplicate or invalid event id at line %d", lineNumber)
		}
		s.eventIDs[event.ID] = true
		s.events = append(s.events, event)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan event store: %w", err)
	}
	afterRead, err := f.Stat()
	if err != nil || !os.SameFile(opened, afterRead) || afterRead.Size() != opened.Size() {
		return fmt.Errorf("event store changed while reading")
	}
	if err := verifyEventChain(s.events); err != nil {
		return fmt.Errorf("stored evidence integrity failure: %w", err)
	}
	if len(s.events) > 0 && s.events[0].PrevHash != "" {
		return fmt.Errorf("stored evidence integrity failure: chain does not begin at genesis")
	}
	s.rebuildIndex()
	return nil
}

// Healthy reports whether a prior append, sync, or retention failure poisoned
// the store. A poisoned store requires operator recovery and restart.
func (s *EventStore) Healthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.poisoned == nil
}

func ensureJSONDecoderEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func (s *EventStore) rebuildIndex() {
	s.sessions = make(map[string][]int)
	s.eventIDs = make(map[string]bool)
	s.lastHash = ""
	for i := range s.events {
		s.sessions[s.events[i].SessionID] = append(s.sessions[s.events[i].SessionID], i)
		s.eventIDs[s.events[i].ID] = true
		s.lastHash = s.events[i].Hash
	}
}

// purgeExpired removes events older than the configured TTL and rewrites the file.
func (s *EventStore) purgeExpired() error {
	if s.retention.ExpireAfterDays <= 0 {
		return nil
	}

	cutoff := time.Now().UTC().Add(-time.Duration(s.retention.ExpireAfterDays) * 24 * time.Hour)
	var kept []Event

	for _, e := range s.events {
		ts, ok := parseTimestamp(e.Timestamp)
		if ok && ts.Before(cutoff) {
			continue // expired
		}
		kept = append(kept, e)
	}

	removed := len(s.events) - len(kept)
	if removed == 0 {
		return nil
	}

	// Re-chain retained records so the persisted evidence remains internally
	// verifiable after policy-authorized retention removes a prefix or gap.
	previous := ""
	for i := range kept {
		kept[i].PrevHash = previous
		kept[i].Hash = computeEventHash(kept[i])
		previous = kept[i].Hash
	}
	// Rewrite the file before committing the new in-memory view. If persistence
	// fails, callers continue to see the original complete evidence set.
	committed, err := s.rewriteFile(kept)
	if committed {
		s.events = kept
		s.rebuildIndex()
	}
	return err
}

// PurgeExpired is the exported version for use by the daemon's periodic ticker.
func (s *EventStore) PurgeExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned != nil {
		return fmt.Errorf("event store is poisoned: %w", s.poisoned)
	}
	if err := s.purgeExpired(); err != nil {
		s.poisoned = err
		return err
	}
	return nil
}

// rewriteFile replaces the events JSONL file with current in-memory state.
func (s *EventStore) rewriteFile(events []Event) (bool, error) {
	tmp, err := os.CreateTemp(filepath.Dir(s.filePath), ".events-*.tmp")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return false, err
	}
	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			cleanup()
			return false, err
		}
		if _, err := tmp.Write(append(data, '\n')); err != nil {
			cleanup()
			return false, err
		}
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return false, err
	}
	// #nosec G304 -- tmpPath was returned by os.CreateTemp in the trusted store directory during this transaction.
	newFile, err := os.OpenFile(tmpPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Remove(tmpPath)
		return false, err
	}
	dir, err := os.Open(filepath.Dir(s.filePath))
	if err != nil {
		newFile.Close()
		os.Remove(tmpPath)
		return false, err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		dir.Close()
		newFile.Close()
		os.Remove(tmpPath)
		return false, err
	}
	oldFile := s.file
	s.file = newFile
	if oldFile != nil {
		_ = oldFile.Close()
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return true, err
	}
	if err := dir.Close(); err != nil {
		return true, err
	}
	return true, nil
}

// Record adds an event to the store with ID, timestamp, and hash chain.
// Enforces retention limits (max_events_per_session, max_sessions).
func (s *EventStore) Record(e Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned != nil {
		return Event{}, fmt.Errorf("event store is poisoned: %w", s.poisoned)
	}

	// Enforce retention: max events per session.
	if s.retention.MaxEventsPerSession > 0 {
		if len(s.sessions[e.SessionID]) >= s.retention.MaxEventsPerSession {
			return Event{}, fmt.Errorf("session %q at max events (%d)", e.SessionID, s.retention.MaxEventsPerSession)
		}
	}

	// Enforce retention: max sessions.
	if s.retention.MaxSessions > 0 && e.SessionID != "" {
		if _, exists := s.sessions[e.SessionID]; !exists {
			if len(s.sessions) >= s.retention.MaxSessions {
				return Event{}, fmt.Errorf("max sessions reached (%d)", s.retention.MaxSessions)
			}
		}
	}

	// Assign metadata.
	if e.ID == "" {
		e.ID = generateID()
	}
	if !validObjectID(e.ID) || s.eventIDs[e.ID] {
		return Event{}, fmt.Errorf("event id is invalid or already exists")
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	if err := validateEvent(e); err != nil {
		return Event{}, err
	}
	if s.file == nil {
		return Event{}, fmt.Errorf("event store is closed")
	}

	// Chain linkage.
	e.PrevHash = s.lastHash
	e.Hash = computeEventHash(e)

	// Persist to file.
	data, err := json.Marshal(e)
	if err != nil {
		return e, fmt.Errorf("marshal event: %w", err)
	}
	if len(data) > maxStoredEventLine {
		return e, fmt.Errorf("event exceeds %d-byte limit", maxStoredEventLine)
	}
	line := append(data, '\n')
	fileInfo, err := s.file.Stat()
	if err != nil {
		s.poisoned = fmt.Errorf("stat event file: %w", err)
		return e, s.poisoned
	}
	pathInfo, pathErr := os.Lstat(s.filePath)
	if pathErr != nil || !os.SameFile(fileInfo, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 ||
		fileInfo.Mode().Perm()&0o077 != 0 || !trustedFileOwner(fileInfo) {
		s.poisoned = fmt.Errorf("event store path changed or became unsafe")
		return e, s.poisoned
	}
	if fileInfo.Size() > maxEventStoreSize-int64(len(line)) {
		return e, fmt.Errorf("projected event store size exceeds %d bytes", maxEventStoreSize)
	}
	written, err := s.file.Write(line)
	if err != nil || written != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
		s.poisoned = fmt.Errorf("write event: %w", err)
		return e, s.poisoned
	}
	// fsync to ensure durability.
	if err := s.file.Sync(); err != nil {
		s.poisoned = fmt.Errorf("sync event file: %w", err)
		return e, s.poisoned
	}

	// Update in-memory index.
	var stored Event
	if err := json.Unmarshal(data, &stored); err != nil {
		return e, fmt.Errorf("copy event: %w", err)
	}
	idx := len(s.events)
	s.events = append(s.events, stored)
	s.sessions[e.SessionID] = append(s.sessions[e.SessionID], idx)
	s.eventIDs[e.ID] = true
	s.lastHash = e.Hash

	return e, nil
}

// Query returns events matching the filter criteria.
// Time filtering uses parsed timestamps for correctness across formats.
func (s *EventStore) Query(filter EventFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Event

	// Parse filter timestamps once (outside the loop).
	var afterTime, beforeTime time.Time
	var hasAfter, hasBefore bool
	if filter.After != "" {
		if t, ok := parseTimestamp(filter.After); ok {
			afterTime = t
			hasAfter = true
		}
	}
	if filter.Before != "" {
		if t, ok := parseTimestamp(filter.Before); ok {
			beforeTime = t
			hasBefore = true
		}
	}

	// If filtering by session, use the index.
	var candidates []Event
	if filter.SessionID != "" {
		indices, ok := s.sessions[filter.SessionID]
		if !ok {
			return nil
		}
		for _, idx := range indices {
			candidates = append(candidates, s.events[idx])
		}
	} else {
		candidates = s.events
	}

	for _, e := range candidates {
		if filter.Source != "" && e.Source != filter.Source {
			continue
		}
		if filter.Type != "" && e.Type != filter.Type {
			continue
		}
		if filter.Severity != "" && e.Severity != filter.Severity {
			continue
		}
		if hasAfter {
			if et, ok := parseTimestamp(e.Timestamp); ok {
				if et.Before(afterTime) {
					continue
				}
			}
		}
		if hasBefore {
			if et, ok := parseTimestamp(e.Timestamp); ok {
				if et.After(beforeTime) {
					continue
				}
			}
		}
		data, err := json.Marshal(e)
		if err != nil {
			continue
		}
		var copied Event
		if err := json.Unmarshal(data, &copied); err != nil {
			continue
		}
		results = append(results, copied)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results
}

// Sessions returns a summary of all recorded sessions.
func (s *EventStore) Sessions() []SessionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var summaries []SessionSummary
	for sid, indices := range s.sessions {
		if len(indices) == 0 {
			continue
		}

		sourceSet := make(map[string]bool)
		first := s.events[indices[0]].Timestamp
		last := s.events[indices[len(indices)-1]].Timestamp

		for _, idx := range indices {
			sourceSet[s.events[idx].Source] = true
		}

		var sources []string
		for src := range sourceSet {
			sources = append(sources, src)
		}
		sort.Strings(sources)

		summaries = append(summaries, SessionSummary{
			SessionID:  sid,
			EventCount: len(indices),
			FirstEvent: first,
			LastEvent:  last,
			Sources:    sources,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].LastEvent > summaries[j].LastEvent
	})
	return summaries
}

// EventCount returns the total number of stored events.
func (s *EventStore) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Close closes the event store file.
func (s *EventStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
