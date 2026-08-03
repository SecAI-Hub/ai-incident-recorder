package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type RecorderPolicy struct {
	Version  int            `yaml:"version"`
	Recorder RecorderConfig `yaml:"recorder"`
}

type RecorderConfig struct {
	DataDir         string                          `yaml:"data_dir"`
	Retention       RetentionConfig                 `yaml:"retention"`
	Redaction       RedactionConfig                 `yaml:"redaction"`
	PrivacyProfiles map[string]PrivacyProfileConfig `yaml:"privacy_profiles"`
	SigningKey      string                          `yaml:"signing_key"`
	Daemon          DaemonConfig                    `yaml:"daemon"`
	RateLimit       RateLimitConfig                 `yaml:"rate_limit"`
}

type RetentionConfig struct {
	MaxEventsPerSession int `yaml:"max_events_per_session"`
	MaxSessions         int `yaml:"max_sessions"`
	ExpireAfterDays     int `yaml:"expire_after_days"`
}

type RedactionConfig struct {
	OnPackage bool     `yaml:"on_package"`
	OnRecord  bool     `yaml:"on_record"`
	Patterns  []string `yaml:"patterns"`
}

type DaemonConfig struct {
	BindAddr        string `yaml:"bind_addr"`
	ReadTimeoutSec  int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSec  int    `yaml:"idle_timeout_seconds"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   RecorderPolicy

	eventStore    *EventStore
	incidentStore *IncidentStore

	auditFile     *os.File
	auditMu       sync.Mutex
	auditPath     string
	auditLastHash string
	auditRequired atomic.Bool
	auditHealthy  atomic.Bool

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests atomic.Int64
	eventRequests atomic.Int64

	serviceToken string
)

const (
	defaultPolicyPath = "/etc/secure-ai/policy/recorder.yaml"
	// #nosec G101 -- this is a filesystem location for a runtime-mounted token, not credential material.
	defaultTokenPath   = "/run/secure-ai/service-token"
	defaultAuditPath   = "/var/lib/secure-ai/logs/recorder-audit.jsonl"
	defaultDataDir     = "/var/lib/secure-ai/incidents"
	defaultBindAddr    = "127.0.0.1:8495"
	defaultRPM         = 120
	maxRequestBodySize = 1 << 20 // 1 MiB
	maxPolicySize      = 1 << 20
	maxAuditSize       = 64 << 20
	maxAuditLine       = 64 << 10
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func loadPolicy() error {
	p, err := parsePolicyFile(policyFilePath())
	if err != nil {
		return err
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded from %s (version=%d)", policyFilePath(), p.Version)
	return nil
}

func parsePolicyFile(path string) (RecorderPolicy, error) {
	data, err := readTrustedConfigFile(path, maxPolicySize)
	if err != nil {
		return RecorderPolicy{}, fmt.Errorf("read policy: %w", err)
	}
	var p RecorderPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return RecorderPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := ensureYAMLEOF(decoder); err != nil {
		return RecorderPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return RecorderPolicy{}, fmt.Errorf("validate policy: %w", err)
	}
	return p, nil
}

func ensureYAMLEOF(decoder *yaml.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}

func validatePolicy(p RecorderPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	r := p.Recorder.Retention
	if r.MaxEventsPerSession < 0 || r.MaxSessions < 0 || r.ExpireAfterDays < 0 ||
		p.Recorder.RateLimit.RequestsPerMinute < 0 {
		return fmt.Errorf("retention and rate-limit values cannot be negative")
	}
	if p.Recorder.DataDir != "" && (!filepath.IsAbs(p.Recorder.DataDir) || filepath.Clean(p.Recorder.DataDir) != p.Recorder.DataDir) {
		return fmt.Errorf("data_dir must be canonical and absolute")
	}
	if p.Recorder.SigningKey != "" && (!filepath.IsAbs(p.Recorder.SigningKey) || filepath.Clean(p.Recorder.SigningKey) != p.Recorder.SigningKey) {
		return fmt.Errorf("signing_key must be canonical and absolute")
	}
	knownPatterns := make(map[string]bool, len(defaultRedactionRules))
	for _, rule := range defaultRedactionRules {
		knownPatterns[rule.Name] = true
	}
	checkPatterns := func(patterns []string) error {
		for _, pattern := range patterns {
			if !knownPatterns[pattern] {
				return fmt.Errorf("unknown redaction pattern %q", pattern)
			}
		}
		return nil
	}
	if err := checkPatterns(p.Recorder.Redaction.Patterns); err != nil {
		return err
	}
	for _, profile := range p.Recorder.PrivacyProfiles {
		if err := checkPatterns(profile.Patterns); err != nil {
			return err
		}
	}
	return nil
}

func getPolicy() RecorderPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

func getDataDir() string {
	p := getPolicy()
	if p.Recorder.DataDir != "" {
		return p.Recorder.DataDir
	}
	return defaultDataDir
}

func readTrustedConfigFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 || !trustedFileOwner(before) {
		return nil, fmt.Errorf("policy must be a non-writable regular file owned by root or the service user")
	}
	data, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0o022 != 0 || !trustedFileOwner(after) {
		return nil, fmt.Errorf("policy changed while validating trust")
	}
	return data, nil
}

func trustedFileOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	euid := int64(os.Geteuid())
	return stat.Uid == 0 || (euid >= 0 && int64(stat.Uid) == euid)
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
	PrevHash  string `json:"prev_hash,omitempty"`
	Hash      string `json:"hash"`
}

func initAuditLog() error {
	auditRequired.Store(true)
	auditHealthy.Store(false)
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	if !filepath.IsAbs(auditPath) || filepath.Clean(auditPath) != auditPath {
		return fmt.Errorf("audit path must be canonical and absolute")
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	if info, err := os.Lstat(filepath.Dir(auditPath)); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !trustedFileOwner(info) {
		return fmt.Errorf("audit directory is unsafe")
	}
	if err := verifyRecorderAudit(auditPath); err != nil {
		return err
	}
	f, err := openEventAppend(auditPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	if info, err := f.Stat(); err != nil || info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
		f.Close()
		return fmt.Errorf("audit log permissions or ownership are unsafe")
	}
	auditFile = f
	auditHealthy.Store(true)
	return nil
}

func verifyRecorderAudit(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		auditLastHash = ""
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxAuditSize || info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
		return fmt.Errorf("audit log is unsafe, oversized, or has weak permissions")
	}
	// #nosec G304 -- initAuditLog requires a canonical absolute path and safe parent; identity, owner, mode, and bounds are rechecked here.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return fmt.Errorf("audit log changed while opening")
	}
	scanner := bufio.NewScanner(io.LimitReader(f, maxAuditSize+1))
	scanner.Buffer(make([]byte, 4096), maxAuditLine)
	expectedPrev := ""
	line := 0
	for scanner.Scan() {
		line++
		var entry AuditEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("decode audit line %d: %w", line, err)
		}
		if err := ensureJSONDecoderEOF(decoder); err != nil {
			return fmt.Errorf("decode audit line %d: %w", line, err)
		}
		if entry.Action == "" || entry.PrevHash != expectedPrev || entry.Hash != computeRecorderAuditHash(entry) {
			return fmt.Errorf("audit integrity failure at line %d", line)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
			return fmt.Errorf("invalid audit timestamp at line %d", line)
		}
		expectedPrev = entry.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan audit log: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return fmt.Errorf("audit log changed while reading")
	}
	auditLastHash = expectedPrev
	return nil
}

func computeRecorderAuditHash(entry AuditEntry) string {
	entry.Hash = ""
	data, _ := json.Marshal(entry)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func auditAvailable() bool {
	return !auditRequired.Load() || auditHealthy.Load()
}

func recorderStorageAvailable() bool {
	return eventStore == nil || eventStore.Healthy()
}

func writeAudit(entry AuditEntry) error {
	if auditFile == nil {
		if !auditRequired.Load() {
			return nil
		}
		return fmt.Errorf("audit log is unavailable")
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if !auditHealthy.Load() {
		return fmt.Errorf("audit log is unhealthy")
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	entry.PrevHash = auditLastHash
	entry.Hash = computeRecorderAuditHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		auditHealthy.Store(false)
		return fmt.Errorf("audit marshal: %w", err)
	}
	line := append(data, '\n')
	info, err := auditFile.Stat()
	pathInfo, pathErr := os.Lstat(auditPath)
	if err != nil || pathErr != nil || !os.SameFile(info, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
		auditHealthy.Store(false)
		return fmt.Errorf("audit path changed or became unsafe")
	}
	if info.Size() > maxAuditSize-int64(len(line)) {
		auditHealthy.Store(false)
		return fmt.Errorf("audit log reached its %d-byte rotation limit", maxAuditSize)
	}
	written, err := auditFile.Write(line)
	if err != nil || written != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
		auditHealthy.Store(false)
		return fmt.Errorf("audit write: %w", err)
	}
	if err := auditFile.Sync(); err != nil {
		auditHealthy.Store(false)
		return fmt.Errorf("audit sync: %w", err)
	}
	auditLastHash = entry.Hash
	return nil
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	data, err := readOwnerOnlyFile(tokenPath, 4096)
	if err != nil {
		return fmt.Errorf("read service token: %w", err)
	}
	serviceToken = strings.TrimSpace(string(data))
	if len(serviceToken) < 32 {
		return fmt.Errorf("service token must contain at least 32 characters")
	}
	log.Printf("service token loaded")
	return nil
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			http.Error(w, "service authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		if !auditAvailable() {
			http.Error(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
			return
		}
		if !recorderStorageAvailable() {
			http.Error(w, "event store unavailable", http.StatusServiceUnavailable)
			return
		}
		if !checkRateLimit() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.Recorder.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return ensureJSONDecoderEOF(decoder)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := "ok"
	statusCode := http.StatusOK
	if !auditAvailable() || !recorderStorageAvailable() {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      status,
		"service":     "ai-incident-recorder",
		"event_count": eventStore.EventCount(),
	})
}

func handleRecordEvent(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	eventRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event Event
	if err := decodeRequestJSON(w, r, maxRequestBodySize, &event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateEvent(event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if event.SessionID == "" {
		event.SessionID = "default"
	}

	// Apply on-record redaction if configured.
	pol := getPolicy()
	if pol.Recorder.Redaction.OnRecord {
		stats := &RedactionStats{Counts: make(map[string]int)}
		event = RedactEvent(event, defaultRedactionRules, stats)
	}
	if err := writeAudit(AuditEntry{Action: "event.record_authorized"}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	recorded, err := eventStore.Record(event)
	if err != nil {
		log.Printf("error recording event: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := writeAudit(AuditEntry{Action: "event.recorded", Detail: recorded.ID}); err != nil && auditRequired.Load() {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(recorded)
}

func handleRecordBatch(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	eventRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var events []Event
	if err := decodeRequestJSON(w, r, maxRequestBodySize*10, &events); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(events) == 0 || len(events) > 1000 {
		http.Error(w, "batch must contain between 1 and 1000 events", http.StatusBadRequest)
		return
	}

	pol := getPolicy()
	for i := range events {
		if err := validateEvent(events[i]); err != nil {
			http.Error(w, fmt.Sprintf("invalid event at index %d", i), http.StatusBadRequest)
			return
		}
	}
	if err := writeAudit(AuditEntry{Action: "events.batch_authorized", Detail: fmt.Sprintf("count %d", len(events))}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	var recorded []Event
	for _, event := range events {
		if event.SessionID == "" {
			event.SessionID = "default"
		}

		// Apply on-record redaction (consistent with single event handler).
		if pol.Recorder.Redaction.OnRecord {
			stats := &RedactionStats{Counts: make(map[string]int)}
			event = RedactEvent(event, defaultRedactionRules, stats)
		}

		e, err := eventStore.Record(event)
		if err != nil {
			log.Printf("error recording batch event: %v", err)
			http.Error(w, "batch storage failed", http.StatusInternalServerError)
			return
		}
		recorded = append(recorded, e)
	}

	if err := writeAudit(AuditEntry{Action: "events.batch", Detail: fmt.Sprintf("recorded %d/%d", len(recorded), len(events))}); err != nil && auditRequired.Load() {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"recorded": len(recorded),
		"total":    len(events),
	})
}

func handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	for _, value := range []string{q.Get("after"), q.Get("before")} {
		if value != "" {
			if _, ok := parseTimestamp(value); !ok {
				http.Error(w, "invalid time filter", http.StatusBadRequest)
				return
			}
		}
	}
	filter := EventFilter{
		SessionID: q.Get("session_id"),
		Source:    q.Get("source"),
		Type:      q.Get("type"),
		Severity:  q.Get("severity"),
		After:     q.Get("after"),
		Before:    q.Get("before"),
		Limit:     1000,
	}
	if rawLimit := q.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 1000 {
			http.Error(w, "limit must be between 1 and 1000", http.StatusBadRequest)
			return
		}
		filter.Limit = limit
	}

	events := eventStore.Query(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(events),
		"events": events,
	})
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": eventStore.Sessions(),
	})
}

func handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var inc Incident
	if err := decodeRequestJSON(w, r, maxRequestBodySize, &inc); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateIncident(inc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := writeAudit(AuditEntry{Action: "incident.create_authorized"}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	created, err := incidentStore.Create(inc)
	if err != nil {
		log.Printf("error creating incident: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := writeAudit(AuditEntry{Action: "incident.created", Detail: created.ID}); err != nil && auditRequired.Load() {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func handleListIncidents(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incidents": incidentStore.List(),
	})
}

func handleGetIncident(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if !validObjectID(id) {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	inc, ok := incidentStore.Get(id)
	if !ok {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	// Fetch associated events.
	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	events, err := SelectIncidentEvents(inc, events)
	if err != nil {
		http.Error(w, "incident evidence is incomplete", http.StatusConflict)
		return
	}
	timeline := BuildTimeline(events)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incident": inc,
		"timeline": timeline,
		"events":   len(events),
	})
}

func handlePackageBundle(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if !validObjectID(id) {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	inc, ok := incidentStore.Get(id)
	if !ok {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	events, err := SelectIncidentEvents(inc, events)
	if err != nil {
		http.Error(w, "incident evidence is incomplete", http.StatusConflict)
		return
	}

	pol := getPolicy()
	if pol.Recorder.SigningKey == "" {
		http.Error(w, "evidence signing is not configured", http.StatusServiceUnavailable)
		return
	}
	profileName := r.URL.Query().Get("profile")
	profile, err := resolvePrivacyProfile(pol, profileName)
	if err != nil {
		http.Error(w, "unknown privacy profile", http.StatusBadRequest)
		return
	}
	if err := writeAudit(AuditEntry{Action: "bundle.package_authorized", Detail: inc.ID}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	bundle, err := PackageBundle(inc, events, profile, pol.Recorder.SigningKey)
	if err != nil {
		log.Printf("error packaging bundle: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := writeAudit(AuditEntry{Action: "bundle.packaged", Detail: inc.ID}); err != nil && auditRequired.Load() {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	newPolicy, err := parsePolicyFile(policyFilePath())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	oldPolicy := getPolicy()
	if recorderRestartOnlyChanged(oldPolicy, newPolicy) {
		http.Error(w, "data directory, retention, or daemon changes require a restart", http.StatusConflict)
		return
	}
	if err := writeAudit(AuditEntry{Action: "policy.reload_authorized"}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}
	policyMu.Lock()
	policy = newPolicy
	policyMu.Unlock()
	if err := writeAudit(AuditEntry{Action: "policy.reloaded"}); err != nil && auditRequired.Load() {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func recorderRestartOnlyChanged(oldPolicy, newPolicy RecorderPolicy) bool {
	oldDataDir := oldPolicy.Recorder.DataDir
	if oldDataDir == "" {
		oldDataDir = defaultDataDir
	}
	newDataDir := newPolicy.Recorder.DataDir
	if newDataDir == "" {
		newDataDir = defaultDataDir
	}
	return oldDataDir != newDataDir || oldPolicy.Recorder.Retention != newPolicy.Recorder.Retention ||
		oldPolicy.Recorder.Daemon != newPolicy.Recorder.Daemon
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests": totalRequests.Load(),
		"event_requests": eventRequests.Load(),
		"stored_events":  int64(eventStore.EventCount()),
	})
}

// ---------------------------------------------------------------------------
// Privacy profile resolution
// ---------------------------------------------------------------------------

// resolvePrivacyProfile returns a profile config by name, or falls back to
// the legacy redaction config.
func resolvePrivacyProfile(pol RecorderPolicy, name string) (PrivacyProfileConfig, error) {
	if name != "" {
		if p, ok := pol.Recorder.PrivacyProfiles[name]; ok {
			return p, nil
		}
		return PrivacyProfileConfig{}, fmt.Errorf("unknown privacy profile %q", name)
	}
	return PrivacyProfileConfig{
		Redact:   pol.Recorder.Redaction.OnPackage,
		Patterns: pol.Recorder.Redaction.Patterns,
	}, nil
}

// ---------------------------------------------------------------------------
// Route multiplexer (exported for testing)
// ---------------------------------------------------------------------------

// buildMux constructs the HTTP mux with auth on all non-health endpoints.
func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/event", requireServiceToken(handleRecordEvent))
	mux.HandleFunc("/v1/events", requireServiceToken(handleQueryEvents))
	mux.HandleFunc("/v1/events/batch", requireServiceToken(handleRecordBatch))
	mux.HandleFunc("/v1/sessions", requireServiceToken(handleListSessions))
	mux.HandleFunc("/v1/incident", requireServiceToken(handleGetIncident))
	mux.HandleFunc("/v1/incidents", requireServiceToken(handleListIncidents))
	mux.HandleFunc("/v1/incident/create", requireServiceToken(handleCreateIncident))
	mux.HandleFunc("/v1/incident/package", requireServiceToken(handlePackageBundle))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// Daemon mode
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string) {
	if err := loadServiceToken(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := initAuditLog(); err != nil {
		log.Fatalf("audit durability unavailable: %v", err)
	}

	pol := getPolicy()

	readTimeout := time.Duration(pol.Recorder.Daemon.ReadTimeoutSec) * time.Second
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := time.Duration(pol.Recorder.Daemon.WriteTimeoutSec) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 60 * time.Second
	}
	idleTimeout := time.Duration(pol.Recorder.Daemon.IdleTimeoutSec) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}

	// Start periodic TTL purge if configured.
	if pol.Recorder.Retention.ExpireAfterDays > 0 {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				if err := writeAudit(AuditEntry{Action: "retention.purge_authorized"}); err != nil {
					log.Printf("retention preflight audit failed: %v", err)
					continue
				}
				if err := eventStore.PurgeExpired(); err != nil {
					log.Printf("retention purge failed: %v", err)
					auditHealthy.Store(false)
					continue
				}
				if err := writeAudit(AuditEntry{Action: "retention.purge"}); err != nil {
					log.Printf("retention audit failed: %v", err)
				}
			}
		}()
		log.Printf("TTL purge enabled: expire_after_days=%d", pol.Recorder.Retention.ExpireAfterDays)
	}

	mux := buildMux()

	srv := &http.Server{
		Addr:              bindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("ai-incident-recorder daemon listening on %s (events: %d)", bindAddr, eventStore.EventCount())
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- srv.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("server shutdown failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdRecord(policyPath, bindAddr string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error
	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening event store: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening incident store: %v\n", err)
		return 1
	}

	if bindAddr == "" {
		bindAddr = pol.Recorder.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}

	runDaemon(bindAddr)
	return 0
}

func cmdIngest(policyPath, filePath, source, sessionID string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error
	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening event store: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	data, err := readBoundedRegularFile(filePath, maxEventStoreSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		return 1
	}

	if sessionID == "" {
		sessionID = generateID()
	}

	var pending []Event
	for lineIndex, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&raw); err != nil || raw == nil {
			fmt.Fprintf(os.Stderr, "invalid JSON at line %d; no events imported\n", lineIndex+1)
			return 1
		}
		if err := ensureJSONDecoderEOF(decoder); err != nil {
			fmt.Fprintf(os.Stderr, "trailing JSON at line %d; no events imported\n", lineIndex+1)
			return 1
		}

		event := Event{
			SessionID: sessionID,
			Source:    source,
			Type:      inferEventType(raw, source),
			Data:      raw,
		}

		// Preserve original timestamp if present.
		if ts, ok := raw["timestamp"].(string); ok {
			event.Timestamp = ts
		}

		// Infer severity from the data.
		event.Severity = inferSeverity(raw)
		if pol.Recorder.Redaction.OnRecord {
			stats := &RedactionStats{Counts: make(map[string]int)}
			event = RedactEvent(event, defaultRedactionRules, stats)
		}
		if err := validateEvent(event); err != nil {
			fmt.Fprintf(os.Stderr, "invalid event at line %d: %v; no events imported\n", lineIndex+1, err)
			return 1
		}
		pending = append(pending, event)
	}
	if len(pending) == 0 {
		fmt.Fprintln(os.Stderr, "input contains no events")
		return 1
	}

	count := 0
	for _, event := range pending {
		if _, err := eventStore.Record(event); err != nil {
			fmt.Fprintf(os.Stderr, "ingest failed after %d accepted events; %d events rejected: %v\n", count, len(pending)-count, err)
			return 1
		}
		count++
	}

	fmt.Printf("ingested %d events from %s (session: %s)\n", count, filePath, sessionID)
	return 0
}

func cmdList(policyPath, what string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	switch what {
	case "sessions":
		eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		defer eventStore.Close()

		sessions := eventStore.Sessions()
		if len(sessions) == 0 {
			fmt.Println("no sessions recorded")
			return 0
		}
		for _, s := range sessions {
			fmt.Printf("  %-30s  events=%-5d  sources=%s  range=%s..%s\n",
				s.SessionID, s.EventCount, strings.Join(s.Sources, ","),
				s.FirstEvent, s.LastEvent)
		}

	case "incidents":
		incidentStore, err = NewIncidentStore(dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		incidents := incidentStore.List()
		if len(incidents) == 0 {
			fmt.Println("no incidents recorded")
			return 0
		}
		for _, inc := range incidents {
			fmt.Printf("  %-30s  [%s] %s  (%s)\n",
				inc.ID, inc.Severity, inc.Title, inc.Status)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown list type: %s (use 'sessions' or 'incidents')\n", what)
		return 1
	}
	return 0
}

func cmdShow(policyPath, incidentID string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	inc, ok := incidentStore.Get(incidentID)
	if !ok {
		fmt.Fprintf(os.Stderr, "incident not found: %s\n", incidentID)
		return 1
	}

	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	events, err = SelectIncidentEvents(inc, events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident evidence incomplete: %v\n", err)
		return 1
	}
	timeline := BuildTimeline(events)

	fmt.Printf("Incident: %s\n", inc.Title)
	fmt.Printf("ID:       %s\n", inc.ID)
	fmt.Printf("Severity: %s\n", inc.Severity)
	fmt.Printf("Status:   %s\n", inc.Status)
	fmt.Printf("Created:  %s\n", inc.CreatedAt)
	fmt.Printf("Events:   %d\n\n", len(events))
	fmt.Println("Timeline:")
	fmt.Println(strings.Repeat("-", 80))

	for _, entry := range timeline {
		sev := entry.Severity
		switch sev {
		case "critical":
			sev = "CRIT"
		case "alert":
			sev = "ALRT"
		case "warning":
			sev = "WARN"
		case "info":
			sev = "INFO"
		}
		fmt.Printf("  T+%6dms  [%-4s] %-20s  %s\n",
			entry.RelativeMs, sev, entry.Source, entry.Summary)
	}
	return 0
}

func cmdPackage(policyPath, incidentID, outputPath, keyPath, profileName string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	inc, ok := incidentStore.Get(incidentID)
	if !ok {
		fmt.Fprintf(os.Stderr, "incident not found: %s\n", incidentID)
		return 1
	}

	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	events, err = SelectIncidentEvents(inc, events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "incident evidence incomplete: %v\n", err)
		return 1
	}

	if keyPath != "" {
		pol.Recorder.SigningKey = keyPath
	}

	profile, err := resolvePrivacyProfile(pol, profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error packaging: %v\n", err)
		return 1
	}

	bundle, err := PackageBundle(inc, events, profile, pol.Recorder.SigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error packaging: %v\n", err)
		return 1
	}

	data, _ := json.MarshalIndent(bundle, "", "  ")

	if outputPath != "" && outputPath != "-" {
		if err := writeFileSync(outputPath, append(data, '\n'), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "case bundle written to %s (%d events, %d redactions)\n",
			outputPath, len(bundle.Events), totalRedactions(bundle.Redaction))
	} else {
		fmt.Println(string(data))
	}
	return 0
}

func cmdVerify(bundlePath, pubKeyPath string) int {
	data, err := readBoundedRegularFile(bundlePath, 64<<20)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading bundle: %v\n", err)
		return 1
	}

	var bundle CaseBundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing bundle: %v\n", err)
		return 1
	}
	if err := ensureJSONDecoderEOF(decoder); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing bundle: %v\n", err)
		return 1
	}

	if err := VerifyBundle(&bundle, pubKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
		return 1
	}

	fmt.Printf("bundle verified\n")
	fmt.Printf("  incident:  %s\n", bundle.Title)
	fmt.Printf("  events:    %d\n", len(bundle.Events))
	fmt.Printf("  integrity: %s\n", bundle.Integrity)
	if bundle.Signature != "" {
		fmt.Printf("  signed:    %s\n", bundle.SignedAt)
		fmt.Printf("  signature: valid\n")
	}
	return 0
}

func cmdKeygen(privPath, pubPath string) int {
	if err := generateKeypair(privPath, pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("keypair generated:\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// inferEventType guesses the event type from audit log data and source.
func inferEventType(data map[string]interface{}, source string) string {
	switch source {
	case "tool-firewall":
		return "tool.decision"
	case "airlock":
		return "airlock.request"
	case "registry":
		if _, ok := data["promoted_at"]; ok {
			return "registry.promote"
		}
		return "registry.event"
	case "quarantine":
		return "quarantine.scan"
	case "attestor", "runtime-attestor":
		return "attestor.report"
	default:
		if t, ok := data["type"].(string); ok {
			return t
		}
		return "unknown"
	}
}

// inferSeverity guesses severity from event data.
func inferSeverity(data map[string]interface{}) string {
	if allowed, ok := data["allowed"].(bool); ok && !allowed {
		return "alert"
	}
	if sev, ok := data["severity"].(string); ok {
		return sev
	}
	return "info"
}

func totalRedactions(stats RedactionStats) int {
	total := 0
	for _, c := range stats.Counts {
		total += c
	}
	return total
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "record":
		fs := flag.NewFlagSet("record", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdRecord(*policyPath, *bind))

	case "ingest":
		fs := flag.NewFlagSet("ingest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		filePath := fs.String("file", "", "JSONL file to ingest")
		source := fs.String("source", "", "source service name")
		sessionID := fs.String("session", "", "session ID (auto-generated if empty)")
		fs.Parse(os.Args[2:])
		if *filePath == "" || *source == "" {
			fmt.Fprintf(os.Stderr, "error: -file and -source are required\n")
			os.Exit(1)
		}
		os.Exit(cmdIngest(*policyPath, *filePath, *source, *sessionID))

	case "list":
		fs := flag.NewFlagSet("list", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		fs.Parse(os.Args[2:])
		what := "sessions"
		if fs.NArg() > 0 {
			what = fs.Arg(0)
		}
		os.Exit(cmdList(*policyPath, what))

	case "show":
		fs := flag.NewFlagSet("show", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		id := fs.String("id", "", "incident ID")
		fs.Parse(os.Args[2:])
		if *id == "" {
			fmt.Fprintf(os.Stderr, "error: -id is required\n")
			os.Exit(1)
		}
		os.Exit(cmdShow(*policyPath, *id))

	case "package":
		fs := flag.NewFlagSet("package", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		id := fs.String("id", "", "incident ID")
		output := fs.String("output", "-", "output file (- for stdout)")
		key := fs.String("key", "", "signing key path (overrides policy)")
		profileName := fs.String("profile", "", "privacy profile name (internal, external-share, legal-review)")
		fs.Parse(os.Args[2:])
		if *id == "" {
			fmt.Fprintf(os.Stderr, "error: -id is required\n")
			os.Exit(1)
		}
		os.Exit(cmdPackage(*policyPath, *id, *output, *key, *profileName))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		bundlePath := fs.String("bundle", "", "path to case bundle file")
		pubKey := fs.String("pubkey", "", "path to public key file")
		fs.Parse(os.Args[2:])
		if *bundlePath == "" {
			fmt.Fprintf(os.Stderr, "error: -bundle is required\n")
			os.Exit(1)
		}
		os.Exit(cmdVerify(*bundlePath, *pubKey))

	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		privPath := fs.String("priv", "recorder.key", "private key output path")
		pubPath := fs.String("pub", "recorder.pub", "public key output path")
		fs.Parse(os.Args[2:])
		os.Exit(cmdKeygen(*privPath, *pubPath))

	case "audit-checkpoint":
		fs := flag.NewFlagSet("audit-checkpoint", flag.ExitOnError)
		source := fs.String("audit", defaultAuditPath, "canonical absolute offline audit log path")
		key := fs.String("key", "", "canonical absolute owner-only Ed25519 private key path")
		output := fs.String("output", "", "canonical absolute new checkpoint output path")
		fs.Parse(os.Args[2:])
		if *key == "" || *output == "" {
			fmt.Fprintln(os.Stderr, "error: -key and -output are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditCheckpoint(*source, *key, *output))

	case "audit-verify":
		fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
		checkpoint := fs.String("checkpoint", "", "checkpoint file path")
		pubKey := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		fs.Parse(os.Args[2:])
		if *checkpoint == "" || *pubKey == "" {
			fmt.Fprintln(os.Stderr, "error: -checkpoint and -pubkey are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditVerify(*checkpoint, *pubKey, *requiredHead))

	case "audit-recover":
		fs := flag.NewFlagSet("audit-recover", flag.ExitOnError)
		checkpoint := fs.String("checkpoint", "", "checkpoint file path")
		pubKey := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		output := fs.String("output", "", "canonical absolute new audit log output path (must not exist)")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		fs.Parse(os.Args[2:])
		if *checkpoint == "" || *pubKey == "" || *output == "" || *requiredHead == "" {
			fmt.Fprintln(os.Stderr, "error: -checkpoint, -pubkey, -output, and -require-head are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditRecover(*checkpoint, *pubKey, *output, *requiredHead))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ai-incident-recorder — black box flight recorder for AI agents

Usage:
  ai-incident-recorder <command> [options]

Commands:
  record    Start recording daemon (HTTP API on :8495)
  ingest    Import events from JSONL audit logs
  list      List sessions or incidents
  show      Show incident timeline
  package   Create a signed, redacted case bundle
  verify    Verify case bundle integrity and signature
  keygen    Generate ed25519 signing keypair
  audit-checkpoint  Export a signed, no-overwrite local audit checkpoint
  audit-verify      Verify checkpoint signature, bytes, chain, and optional anchor
  audit-recover     Recover verified bytes to a new path using a retained anchor

Use "ai-incident-recorder <command> -h" for command-specific options.
`)
}
