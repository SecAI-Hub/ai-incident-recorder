package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestStores(t *testing.T) string {
	t.Helper()
	auditRequired.Store(false)
	auditHealthy.Store(false)
	dir := t.TempDir()

	var err error
	eventStore, err = NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}

	incidentStore, err = NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	policyMu.Lock()
	policy = RecorderPolicy{
		Version: 1,
		Recorder: RecorderConfig{
			DataDir: dir,
			Redaction: RedactionConfig{
				OnPackage: true,
				OnRecord:  false,
			},
			RateLimit: RateLimitConfig{RequestsPerMinute: 1000},
		},
	}
	policyMu.Unlock()

	serviceToken = "test-secret"
	t.Cleanup(func() {
		if eventStore != nil {
			eventStore.Close()
			eventStore = nil
		}
		incidentStore = nil
		serviceToken = ""
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
		auditRequired.Store(false)
		auditHealthy.Store(false)
	})
	return dir
}

func authenticatedTestRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer test-secret")
	return req
}

func setupTestStoresWithRetention(t *testing.T, ret RetentionConfig) string {
	t.Helper()
	auditRequired.Store(false)
	auditHealthy.Store(false)
	dir := t.TempDir()

	var err error
	eventStore, err = NewEventStore(dir, ret)
	if err != nil {
		t.Fatal(err)
	}

	incidentStore, err = NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	policyMu.Lock()
	policy = RecorderPolicy{
		Version: 1,
		Recorder: RecorderConfig{
			DataDir:   dir,
			Retention: ret,
			Redaction: RedactionConfig{OnPackage: true, OnRecord: false},
			RateLimit: RateLimitConfig{RequestsPerMinute: 1000},
		},
	}
	policyMu.Unlock()

	serviceToken = ""
	t.Cleanup(func() {
		if eventStore != nil {
			eventStore.Close()
			eventStore = nil
		}
		incidentStore = nil
		serviceToken = ""
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
		auditRequired.Store(false)
		auditHealthy.Store(false)
	})
	return dir
}

// ---------------------------------------------------------------------------
// Event store tests
// ---------------------------------------------------------------------------

func TestEventStore_RecordAndQuery(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Record events.
	e1, err := store.Record(Event{
		SessionID: "sess-1",
		Source:    "tool-firewall",
		Type:      "tool.decision",
		Severity:  "info",
		Data:      map[string]interface{}{"tool": "filesystem.read", "allowed": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e1.ID == "" {
		t.Fatal("expected event ID")
	}
	if e1.Hash == "" {
		t.Fatal("expected event hash")
	}

	e2, err := store.Record(Event{
		SessionID: "sess-1",
		Source:    "model",
		Type:      "model.invoke",
		Data:      map[string]interface{}{"model": "mistral-7b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Chain linkage.
	if e2.PrevHash != e1.Hash {
		t.Fatalf("expected chain: e2.PrevHash=%s, e1.Hash=%s", e2.PrevHash, e1.Hash)
	}

	// Query by session.
	results := store.Query(EventFilter{SessionID: "sess-1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events, got %d", len(results))
	}

	// Query by source.
	results = store.Query(EventFilter{Source: "model"})
	if len(results) != 1 {
		t.Fatalf("expected 1 model event, got %d", len(results))
	}

	// Count.
	if store.EventCount() != 2 {
		t.Fatalf("expected 2 total events, got %d", store.EventCount())
	}
}

func TestEventStore_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Write events.
	store1, _ := NewEventStore(dir, RetentionConfig{})
	store1.Record(Event{SessionID: "s1", Source: "a", Type: "t1"})
	store1.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})
	store1.Close()

	// Reopen and verify.
	store2, _ := NewEventStore(dir, RetentionConfig{})
	defer store2.Close()

	if store2.EventCount() != 2 {
		t.Fatalf("expected 2 persisted events, got %d", store2.EventCount())
	}
}

func TestEventStoreWriteFailurePoisonsFutureWrites(t *testing.T) {
	store, err := NewEventStore(t.TempDir(), RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(Event{SessionID: "s1", Source: "test", Type: "event"}); err == nil {
		t.Fatal("write to closed store must fail")
	}
	if _, err := store.Record(Event{SessionID: "s1", Source: "test", Type: "event"}); err == nil || !strings.Contains(err.Error(), "poisoned") {
		t.Fatalf("subsequent write must be refused by poisoned store: %v", err)
	}
}

func TestEventStore_Sessions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "alpha", Source: "a", Type: "t"})
	store.Record(Event{SessionID: "alpha", Source: "b", Type: "t"})
	store.Record(Event{SessionID: "beta", Source: "c", Type: "t"})

	sessions := store.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// Hash chain tests
// ---------------------------------------------------------------------------

func TestEventChain_Integrity(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t1"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t2"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t3"})

	events := store.Query(EventFilter{SessionID: "s"})
	if err := verifyEventChain(events); err != nil {
		t.Fatalf("chain should be valid: %v", err)
	}
}

func TestEventChain_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t1"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t2"})

	events := store.Query(EventFilter{SessionID: "s"})

	// Tamper with the first event.
	events[0].Source = "TAMPERED"

	if err := verifyEventChain(events); err == nil {
		t.Fatal("expected chain verification to fail on tampered event")
	}
}

// ---------------------------------------------------------------------------
// Retention enforcement tests
// ---------------------------------------------------------------------------

func TestRetention_MaxEventsPerSession(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{MaxEventsPerSession: 3})
	defer store.Close()

	for i := 0; i < 3; i++ {
		_, err := store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
		if err != nil {
			t.Fatalf("event %d should succeed: %v", i, err)
		}
	}

	// 4th event should fail.
	_, err := store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	if err == nil {
		t.Fatal("expected error for exceeding max_events_per_session")
	}
	if !strings.Contains(err.Error(), "max events") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Different session should still work.
	_, err = store.Record(Event{SessionID: "s2", Source: "a", Type: "t"})
	if err != nil {
		t.Fatalf("different session should succeed: %v", err)
	}
}

func TestRetention_ExpireAfterDays(t *testing.T) {
	dir := t.TempDir()

	// Write events with old timestamps directly to the file.
	filePath := dir + "/events.jsonl"
	oldTS := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)
	recentTS := time.Now().UTC().Add(-10 * 24 * time.Hour).Format(time.RFC3339Nano)

	oldEvent := Event{ID: "old-1", Timestamp: oldTS, SessionID: "s1", Source: "a", Type: "t", Severity: "info"}
	oldEvent.Hash = computeEventHash(oldEvent)
	recentEvent := Event{ID: "new-1", Timestamp: recentTS, SessionID: "s1", Source: "a", Type: "t", Severity: "info", PrevHash: oldEvent.Hash}
	recentEvent.Hash = computeEventHash(recentEvent)

	f, _ := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	data1, _ := json.Marshal(oldEvent)
	data2, _ := json.Marshal(recentEvent)
	f.Write(append(data1, '\n'))
	f.Write(append(data2, '\n'))
	f.Close()

	// Open store with 90-day TTL -- should purge the 100-day-old event.
	store, err := NewEventStore(dir, RetentionConfig{ExpireAfterDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if store.EventCount() != 1 {
		t.Fatalf("expected 1 event after TTL purge, got %d", store.EventCount())
	}

	// The remaining event should be the recent one.
	events := store.Query(EventFilter{SessionID: "s1"})
	if len(events) != 1 || events[0].ID != "new-1" {
		t.Fatalf("expected recent event to survive, got %v", events)
	}
}

func TestRetention_MaxSessions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{MaxSessions: 2})
	defer store.Close()

	store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	store.Record(Event{SessionID: "s2", Source: "a", Type: "t"})

	// 3rd session should fail.
	_, err := store.Record(Event{SessionID: "s3", Source: "a", Type: "t"})
	if err == nil {
		t.Fatal("expected error for exceeding max_sessions")
	}
	if !strings.Contains(err.Error(), "max sessions") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Existing session should still accept events.
	_, err = store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	if err != nil {
		t.Fatalf("existing session should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Parsed timestamp query tests
// ---------------------------------------------------------------------------

func TestQuery_ParsedTimestamps(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T10:00:00Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T12:00:00Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T14:00:00Z"})

	// Query with after filter.
	results := store.Query(EventFilter{After: "2026-03-09T11:00:00Z"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events after 11:00, got %d", len(results))
	}

	// Query with before filter.
	results = store.Query(EventFilter{Before: "2026-03-09T13:00:00Z"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events before 13:00, got %d", len(results))
	}

	// Query with both.
	results = store.Query(EventFilter{After: "2026-03-09T11:00:00Z", Before: "2026-03-09T13:00:00Z"})
	if len(results) != 1 {
		t.Fatalf("expected 1 event between 11:00 and 13:00, got %d", len(results))
	}
}

func TestQuery_ParsedTimestamps_DifferentFormats(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	// Events with nanosecond timestamps.
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T10:00:00.000000000Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T12:00:00.500000000Z"})

	// Query with plain RFC3339 filter.
	results := store.Query(EventFilter{After: "2026-03-09T11:00:00Z"})
	if len(results) != 1 {
		t.Fatalf("expected 1 event with cross-format filter, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Redaction tests
// ---------------------------------------------------------------------------

func TestRedactString_Email(t *testing.T) {
	input := "Contact user@example.com for help"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "user@example.com") {
		t.Fatal("email should be redacted")
	}
	if !strings.Contains(result, "[REDACTED:email]") {
		t.Fatal("expected [REDACTED:email] tag")
	}
	if stats.Counts["email"] != 1 {
		t.Fatalf("expected 1 email redaction, got %d", stats.Counts["email"])
	}
}

func TestRedactString_SSN(t *testing.T) {
	input := "SSN: 123-45-6789"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "123-45-6789") {
		t.Fatal("SSN should be redacted")
	}
	if !strings.Contains(result, "[REDACTED:ssn]") {
		t.Fatal("expected [REDACTED:ssn] tag")
	}
}

func TestRedactString_Credential(t *testing.T) {
	input := "password=s3cret123!"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "s3cret123") {
		t.Fatal("credential should be redacted")
	}
}

func TestRedactMap_Nested(t *testing.T) {
	data := map[string]interface{}{
		"prompt": "Send email to admin@corp.com",
		"nested": map[string]interface{}{
			"token": "bearer abc123def456",
		},
	}

	stats := &RedactionStats{Counts: make(map[string]int)}
	redacted := RedactMap(data, defaultRedactionRules, stats)

	prompt := redacted["prompt"].(string)
	if strings.Contains(prompt, "admin@corp.com") {
		t.Fatal("nested email should be redacted")
	}

	nested := redacted["nested"].(map[string]interface{})
	token := nested["[REDACTED:key]"].(string)
	if strings.Contains(token, strings.Join([]string{"abc123", "def456"}, "")) {
		t.Fatal("bearer token should be redacted")
	}
}

func TestRedactMapKeysAreCollisionSafe(t *testing.T) {
	stats := &RedactionStats{Counts: make(map[string]int)}
	redacted := RedactMap(map[string]interface{}{"secret": "one", "token": "two"}, defaultRedactionRules, stats)
	if len(redacted) != 2 || redacted["[REDACTED:key]"] == nil || redacted["[REDACTED:key]#2"] == nil {
		t.Fatalf("sensitive key redaction lost data during collision: %#v", redacted)
	}
}

func TestRedactEvent_PreservesOriginal(t *testing.T) {
	original := Event{
		Source: "test",
		Actor:  "user@example.com",
		Data: map[string]interface{}{
			"content": "SSN is 123-45-6789",
		},
	}

	stats := &RedactionStats{Counts: make(map[string]int)}
	redacted := RedactEvent(original, defaultRedactionRules, stats)

	// Original should be unchanged.
	if original.Actor != "user@example.com" {
		t.Fatal("original event should not be modified")
	}

	// Redacted should have tags.
	if !strings.Contains(redacted.Actor, "[REDACTED:email]") {
		t.Fatal("actor should be redacted in copy")
	}
}

// ---------------------------------------------------------------------------
// Batch redaction consistency test
// ---------------------------------------------------------------------------

func TestBatchRedaction_ConsistentWithSingle(t *testing.T) {
	setupTestStores(t)

	// Enable on-record redaction.
	policyMu.Lock()
	policy.Recorder.Redaction.OnRecord = true
	policyMu.Unlock()

	mux := buildMux()

	// Record via single endpoint.
	body := `{"session_id":"s1","source":"model","type":"model.invoke","data":{"prompt":"Contact admin@corp.com"}}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("single event: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var singleEvent Event
	json.Unmarshal(w.Body.Bytes(), &singleEvent)

	// Record via batch endpoint.
	batchBody := `[{"session_id":"s2","source":"model","type":"model.invoke","data":{"prompt":"Contact admin@corp.com"}}]`
	req = authenticatedTestRequest(http.MethodPost, "/v1/events/batch", strings.NewReader(batchBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("batch: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Query the batch event.
	batchEvents := eventStore.Query(EventFilter{SessionID: "s2"})
	if len(batchEvents) != 1 {
		t.Fatalf("expected 1 batch event, got %d", len(batchEvents))
	}

	// Both should have redacted the email.
	singlePrompt := singleEvent.Data["prompt"].(string)
	batchPrompt := batchEvents[0].Data["prompt"].(string)

	if strings.Contains(singlePrompt, "admin@corp.com") {
		t.Fatal("single event should have redacted email")
	}
	if strings.Contains(batchPrompt, "admin@corp.com") {
		t.Fatal("batch event should have redacted email (consistency fix)")
	}
}

// ---------------------------------------------------------------------------
// Incident and timeline tests
// ---------------------------------------------------------------------------

func TestIncidentStore_CreateAndGet(t *testing.T) {
	dir := t.TempDir()
	store, err := NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	inc, err := store.Create(Incident{
		SessionID: "sess-1",
		Title:     "Suspicious tool call denied",
		Severity:  "alert",
	})
	if err != nil {
		t.Fatal(err)
	}

	if inc.ID == "" {
		t.Fatal("expected incident ID")
	}
	if inc.Status != "open" {
		t.Fatalf("expected status open, got %s", inc.Status)
	}

	// Get.
	retrieved, ok := store.Get(inc.ID)
	if !ok {
		t.Fatal("incident not found")
	}
	if retrieved.Title != "Suspicious tool call denied" {
		t.Fatalf("wrong title: %s", retrieved.Title)
	}
}

func TestIncidentStore_Persistence(t *testing.T) {
	dir := t.TempDir()

	store1, _ := NewIncidentStore(dir)
	store1.Create(Incident{Title: "Test", SessionID: "s1"})

	// Reopen.
	store2, _ := NewIncidentStore(dir)
	incidents := store2.List()
	if len(incidents) != 1 {
		t.Fatalf("expected 1 persisted incident, got %d", len(incidents))
	}
}

func TestBuildTimeline(t *testing.T) {
	events := []Event{
		{ID: "3", Timestamp: "2026-03-09T10:00:02.000Z", Source: "airlock", Type: "airlock.request", Severity: "warning",
			Data: map[string]interface{}{"destination": "https://unknown.com", "allowed": false}},
		{ID: "1", Timestamp: "2026-03-09T10:00:00.000Z", Source: "model", Type: "model.invoke", Severity: "info",
			Data: map[string]interface{}{"model": "mistral-7b"}},
		{ID: "2", Timestamp: "2026-03-09T10:00:01.000Z", Source: "tool-firewall", Type: "tool.decision", Severity: "alert",
			Data: map[string]interface{}{"tool": "shell.exec", "allowed": false, "reason": "denied"}},
	}

	timeline := BuildTimeline(events)
	if len(timeline) != 3 {
		t.Fatalf("expected 3 timeline entries, got %d", len(timeline))
	}

	// Should be sorted by timestamp.
	if timeline[0].EventID != "1" {
		t.Fatalf("first entry should be event 1, got %s", timeline[0].EventID)
	}
	if timeline[0].RelativeMs != 0 {
		t.Fatalf("first entry relative_ms should be 0, got %d", timeline[0].RelativeMs)
	}
	if timeline[1].RelativeMs != 1000 {
		t.Fatalf("second entry relative_ms should be 1000, got %d", timeline[1].RelativeMs)
	}
}

// ---------------------------------------------------------------------------
// Case bundle tests
// ---------------------------------------------------------------------------

func TestPackageBundle_Unsigned(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t1", Data: map[string]interface{}{"info": "test"}})
	es.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test Incident"}

	profile := PrivacyProfileConfig{Redact: true}
	bundle, err := PackageBundle(inc, events, profile, "")
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Integrity == "" {
		t.Fatal("expected integrity hash")
	}
	if len(bundle.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(bundle.Events))
	}
	if len(bundle.Timeline) != 2 {
		t.Fatalf("expected 2 timeline entries, got %d", len(bundle.Timeline))
	}
}

func TestPackageBundle_SignedAndVerified(t *testing.T) {
	dir := t.TempDir()

	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "x", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Signed Test"}

	profile := PrivacyProfileConfig{Redact: false}
	bundle, err := PackageBundle(inc, events, profile, privPath)
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Signature == "" {
		t.Fatal("expected signature")
	}

	// Verify.
	if err := VerifyBundle(bundle, pubPath); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestGenerateKeypairRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	if err := generateKeypair(privPath, pubPath); err != nil {
		t.Fatalf("first keygen: %v", err)
	}
	before, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := generateKeypair(privPath, filepath.Join(dir, "second.pub")); err == nil {
		t.Fatal("key generation must not overwrite an existing private key")
	}
	after, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing private key changed")
	}
}

func TestPackageBundle_TamperDetection(t *testing.T) {
	dir := t.TempDir()

	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "x", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false}
	bundle, _ := PackageBundle(inc, events, profile, privPath)

	// Tamper.
	bundle.Title = "TAMPERED"

	if err := VerifyBundle(bundle, pubPath); err == nil {
		t.Fatal("expected verification to fail on tampered bundle")
	}
}

func TestPackageBundle_Redaction(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{
		SessionID: "s1",
		Source:    "model",
		Type:      "model.invoke",
		Data: map[string]interface{}{
			"prompt": "Contact admin@corp.com about SSN 123-45-6789",
		},
	})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "PII Test"}

	profile := PrivacyProfileConfig{Redact: true}
	bundle, _ := PackageBundle(inc, events, profile, "")

	prompt := bundle.Events[0].Data["prompt"].(string)
	if strings.Contains(prompt, "admin@corp.com") {
		t.Fatal("email should be redacted in bundle")
	}
	if strings.Contains(prompt, "123-45-6789") {
		t.Fatal("SSN should be redacted in bundle")
	}

	// Verify redaction stats.
	if bundle.Redaction.Counts["email"] < 1 {
		t.Fatal("expected email redaction count")
	}
	if bundle.Redaction.Counts["ssn"] < 1 {
		t.Fatal("expected ssn redaction count")
	}
}

func TestPackageBundle_RedactsIncidentMetadata(t *testing.T) {
	incident := &Incident{
		ID: "inc-1", SessionID: "s1", Title: "Contact admin@example.com",
		Notes: "password=fixture-secret", Tags: []string{"admin@example.com"},
	}
	bundle, err := PackageBundle(incident, nil, PrivacyProfileConfig{Redact: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "admin@example.com") || strings.Contains(text, "fixture-secret") {
		t.Fatal("incident title, notes, or tags leaked into redacted bundle")
	}
	if bundle.Title != bundle.Incident.Title {
		t.Fatal("bundle title and embedded incident title must remain consistent")
	}
}

// ---------------------------------------------------------------------------
// Privacy profile tests
// ---------------------------------------------------------------------------

func TestPrivacyProfile_StripHostname(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false, StripHostname: true}
	bundle, _ := PackageBundle(inc, events, profile, "")

	if bundle.Hostname != "[REDACTED]" {
		t.Fatalf("expected hostname to be [REDACTED], got %s", bundle.Hostname)
	}
}

func TestPrivacyProfile_NoStripHostname(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false, StripHostname: false}
	bundle, _ := PackageBundle(inc, events, profile, "")

	if bundle.Hostname == "[REDACTED]" {
		t.Fatal("hostname should not be redacted when StripHostname is false")
	}
}

func TestResolvePrivacyProfile_Named(t *testing.T) {
	pol := RecorderPolicy{
		Recorder: RecorderConfig{
			PrivacyProfiles: map[string]PrivacyProfileConfig{
				"external-share": {
					Redact:        true,
					StripHostname: true,
					Patterns:      []string{"ssn", "email"},
				},
			},
		},
	}

	profile, err := resolvePrivacyProfile(pol, "external-share")
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Redact {
		t.Fatal("expected Redact=true")
	}
	if !profile.StripHostname {
		t.Fatal("expected StripHostname=true")
	}
	if len(profile.Patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(profile.Patterns))
	}
}

func TestResolvePrivacyProfile_FallbackToDefault(t *testing.T) {
	pol := RecorderPolicy{
		Recorder: RecorderConfig{
			Redaction: RedactionConfig{
				OnPackage: true,
				Patterns:  []string{"ssn", "email", "credential"},
			},
		},
	}

	profile, err := resolvePrivacyProfile(pol, "")
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Redact {
		t.Fatal("expected Redact=true from fallback")
	}
	if len(profile.Patterns) != 3 {
		t.Fatalf("expected 3 patterns from fallback, got %d", len(profile.Patterns))
	}
}

func TestResolvePrivacyProfile_UnknownFailsClosed(t *testing.T) {
	if _, err := resolvePrivacyProfile(RecorderPolicy{}, "missing"); err == nil {
		t.Fatal("unknown privacy profile must not silently use weaker defaults")
	}
}

// ---------------------------------------------------------------------------
// Schema validation tests
// ---------------------------------------------------------------------------

func TestValidateEvent_Valid(t *testing.T) {
	e := Event{Source: "tool-firewall", Type: "tool.decision", Severity: "info"}
	if err := validateEvent(e); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateEvent_MissingSource(t *testing.T) {
	e := Event{Type: "tool.decision"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestValidateEvent_MissingType(t *testing.T) {
	e := Event{Source: "tool-firewall"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestValidateEvent_InvalidSeverity(t *testing.T) {
	e := Event{Source: "a", Type: "t", Severity: "bogus"}
	err := validateEvent(e)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEvent_InvalidSourceFormat(t *testing.T) {
	e := Event{Source: "has spaces", Type: "t"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid source format")
	}
}

func TestValidateEvent_InvalidTypeFormat(t *testing.T) {
	e := Event{Source: "a", Type: "has spaces"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid type format")
	}
}

func TestValidateEvent_SessionIDTooLong(t *testing.T) {
	e := Event{Source: "a", Type: "t", SessionID: strings.Repeat("x", 200)}
	err := validateEvent(e)
	if err == nil {
		t.Fatal("expected error for session_id too long")
	}
	if !strings.Contains(err.Error(), "session_id too long") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEvent_InvalidTimestamp(t *testing.T) {
	e := Event{Source: "a", Type: "t", Timestamp: "not-a-timestamp"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

func TestValidateEvent_ValidTimestampFormats(t *testing.T) {
	for _, ts := range []string{
		"2026-03-09T10:00:00Z",
		"2026-03-09T10:00:00.123456789Z",
		"2026-03-09T10:00:00+05:00",
	} {
		e := Event{Source: "a", Type: "t", Timestamp: ts}
		if err := validateEvent(e); err != nil {
			t.Errorf("timestamp %q should be valid: %v", ts, err)
		}
	}
}

func TestValidateIncident_Valid(t *testing.T) {
	inc := Incident{Title: "Test", Severity: "alert", Status: "open"}
	if err := validateIncident(inc); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateIncident_MissingTitle(t *testing.T) {
	inc := Incident{}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestValidateIncident_InvalidSeverity(t *testing.T) {
	inc := Incident{Title: "Test", Severity: "panic"}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestValidateIncident_InvalidStatus(t *testing.T) {
	inc := Incident{Title: "Test", Status: "deleted"}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

// ---------------------------------------------------------------------------
// Event summary tests
// ---------------------------------------------------------------------------

func TestSummarizeEvent(t *testing.T) {
	tests := []struct {
		event    Event
		contains string
	}{
		{
			Event{Type: "tool.decision", Data: map[string]interface{}{"tool": "shell.exec", "allowed": false, "reason": "denied"}},
			"DENIED",
		},
		{
			Event{Type: "model.invoke", Data: map[string]interface{}{"model": "mistral-7b"}},
			"mistral-7b",
		},
		{
			Event{Type: "airlock.request", Data: map[string]interface{}{"destination": "https://hf.co", "allowed": true}},
			"allowed",
		},
		{
			Event{Type: "attestor.report", Data: map[string]interface{}{"verdict": "drift"}},
			"DRIFT",
		},
	}

	for _, tt := range tests {
		summary := summarizeEvent(tt.event)
		if !strings.Contains(summary, tt.contains) {
			t.Errorf("summary for %s should contain %q, got: %s", tt.event.Type, tt.contains, summary)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests (via buildMux)
// ---------------------------------------------------------------------------

func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	setupTestStores(t)
	serviceToken = "secret-token"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	// Health should work without auth.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["service"] != "ai-incident-recorder" {
		t.Fatalf("unexpected service: %v", resp["service"])
	}
}

func TestAllEndpointsRequireAuth(t *testing.T) {
	setupTestStores(t)
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/event"},
		{http.MethodGet, "/v1/events"},
		{http.MethodPost, "/v1/events/batch"},
		{http.MethodGet, "/v1/sessions"},
		{http.MethodGet, "/v1/incident?id=test"},
		{http.MethodGet, "/v1/incidents"},
		{http.MethodPost, "/v1/incident/create"},
		{http.MethodPost, "/v1/incident/package?id=test"},
		{http.MethodPost, "/v1/reload"},
		{http.MethodGet, "/v1/metrics"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 without token, got %d", ep.method, ep.path, w.Code)
		}
	}
}

func TestEndpointsWorkWithValidAuth(t *testing.T) {
	setupTestStores(t)
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	// Record an event with valid auth.
	body := `{"session_id":"s1","source":"tool-firewall","type":"tool.decision","severity":"info"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 with valid auth, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecordEventEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"test-sess","source":"tool-firewall","type":"tool.decision","severity":"info","data":{"tool":"fs.read","allowed":true}}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var event Event
	json.Unmarshal(w.Body.Bytes(), &event)
	if event.ID == "" {
		t.Fatal("expected event ID in response")
	}
	if event.Hash == "" {
		t.Fatal("expected event hash in response")
	}
}

func TestRecordEventEndpoint_ValidationRejectsInvalidSeverity(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"source":"a","type":"t","severity":"bogus"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid severity, got %d", w.Code)
	}
}

func TestRecordEventEndpoint_MissingFields(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"test"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRecordEventEndpoint_WrongMethod(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	req := authenticatedTestRequest(http.MethodGet, "/v1/event", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestQueryEventsEndpoint(t *testing.T) {
	setupTestStores(t)

	// Record some events.
	eventStore.Record(Event{SessionID: "s1", Source: "a", Type: "t1"})
	eventStore.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})
	eventStore.Record(Event{SessionID: "s2", Source: "a", Type: "t1"})

	mux := buildMux()

	req := authenticatedTestRequest(http.MethodGet, "/v1/events?session_id=s1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	count := int(resp["count"].(float64))
	if count != 2 {
		t.Fatalf("expected 2 events for session s1, got %d", count)
	}
}

func TestListSessionsEndpoint(t *testing.T) {
	setupTestStores(t)

	eventStore.Record(Event{SessionID: "alpha", Source: "a", Type: "t"})
	eventStore.Record(Event{SessionID: "beta", Source: "b", Type: "t"})

	mux := buildMux()

	req := authenticatedTestRequest(http.MethodGet, "/v1/sessions", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCreateIncidentEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"s1","title":"Test Incident","severity":"alert"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)
	if inc.ID == "" {
		t.Fatal("expected incident ID")
	}
}

func TestCreateIncidentEndpoint_MissingTitle(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"s1"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCreateIncidentEndpoint_InvalidSeverity(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"title":"Test","severity":"panic"}`
	req := authenticatedTestRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid severity, got %d", w.Code)
	}
}

func TestServiceToken_MissingFailsClosed(t *testing.T) {
	serviceToken = ""
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Fatal("handler must not be called without authentication")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestLoadServiceTokenRequiresOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-token")
	credential := strings.Repeat("x", 32)
	if err := os.WriteFile(path, []byte(credential), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", path)
	if err := loadServiceToken(); err == nil {
		t.Fatal("group/world-readable token must be rejected")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err != nil {
		t.Fatalf("owner-only token rejected: %v", err)
	}
	serviceToken = ""
}

func TestServiceToken_InvalidToken(t *testing.T) {
	serviceToken = "correct-token"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	serviceToken = ""
}

func TestMetricsEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	req := authenticatedTestRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Ingest helper tests
// ---------------------------------------------------------------------------

func TestInferEventType(t *testing.T) {
	tests := []struct {
		source   string
		data     map[string]interface{}
		expected string
	}{
		{"tool-firewall", nil, "tool.decision"},
		{"airlock", nil, "airlock.request"},
		{"registry", map[string]interface{}{"promoted_at": "2026-01-01"}, "registry.promote"},
		{"unknown", map[string]interface{}{"type": "custom.event"}, "custom.event"},
	}

	for _, tt := range tests {
		result := inferEventType(tt.data, tt.source)
		if result != tt.expected {
			t.Errorf("inferEventType(%s) = %s, want %s", tt.source, result, tt.expected)
		}
	}
}

func TestInferSeverity(t *testing.T) {
	if s := inferSeverity(map[string]interface{}{"allowed": false}); s != "alert" {
		t.Errorf("denied action should be alert, got %s", s)
	}
	if s := inferSeverity(map[string]interface{}{"severity": "critical"}); s != "critical" {
		t.Errorf("explicit severity should be preserved, got %s", s)
	}
	if s := inferSeverity(map[string]interface{}{}); s != "info" {
		t.Errorf("default should be info, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Ingest from file test
// ---------------------------------------------------------------------------

func TestIngestFromFile(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	// Create test JSONL file.
	jsonl := `{"timestamp":"2026-03-09T10:00:00Z","tool":"filesystem.read","allowed":true,"reason":"ok"}
{"timestamp":"2026-03-09T10:00:01Z","tool":"shell.exec","allowed":false,"reason":"denied"}
`
	filePath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(filePath, []byte(jsonl), 0644)

	// Simulate ingest.
	data, _ := os.ReadFile(filePath)
	sessionID := "ingest-test"
	source := "tool-firewall"

	var count int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		json.Unmarshal([]byte(line), &raw)

		event := Event{
			SessionID: sessionID,
			Source:    source,
			Type:      inferEventType(raw, source),
			Data:      raw,
			Severity:  inferSeverity(raw),
		}
		if ts, ok := raw["timestamp"].(string); ok {
			event.Timestamp = ts
		}
		es.Record(event)
		count++
	}

	if count != 2 {
		t.Fatalf("expected 2 ingested events, got %d", count)
	}

	events := es.Query(EventFilter{SessionID: sessionID})
	if len(events) != 2 {
		t.Fatalf("expected 2 queryable events, got %d", len(events))
	}
}

// ---------------------------------------------------------------------------
// Corruption tolerance test
// ---------------------------------------------------------------------------

func TestEventStore_CorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/events.jsonl"

	// Write some valid events + a corrupt line.
	valid1 := `{"id":"1","timestamp":"2026-01-01T00:00:00Z","session_id":"s","source":"a","type":"t","severity":"info","hash":"abc"}`
	corrupt := `{CORRUPT LINE`
	valid2 := `{"id":"2","timestamp":"2026-01-01T00:01:00Z","session_id":"s","source":"a","type":"t","severity":"info","hash":"def"}`
	os.WriteFile(filePath, []byte(valid1+"\n"+corrupt+"\n"+valid2+"\n"), 0640)

	store, err := NewEventStore(dir, RetentionConfig{})
	if err == nil || store != nil {
		t.Fatal("corrupt evidence must prevent recorder startup")
	}
}

func TestRetentionRewriteKeepsFutureWritesDurable(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := store.Record(Event{Timestamp: old, SessionID: "s1", Source: "test", Type: "old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(Event{Timestamp: recent, SessionID: "s1", Source: "test", Type: "recent"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	store, err = NewEventStore(dir, RetentionConfig{ExpireAfterDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(Event{SessionID: "s1", Source: "test", Type: "after-purge"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	store, err = NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatalf("reopen after retention and append: %v", err)
	}
	defer store.Close()
	if store.EventCount() != 2 {
		t.Fatalf("expected retained and post-purge events, got %d", store.EventCount())
	}
	if err := verifyEventChain(store.Query(EventFilter{})); err != nil {
		t.Fatalf("rewritten chain is invalid: %v", err)
	}
}

func TestEventStoreQueryReturnsDefensiveCopy(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recorded, err := store.Record(Event{SessionID: "s1", Source: "test", Type: "copy", Data: map[string]any{"value": "original"}})
	if err != nil {
		t.Fatal(err)
	}
	queried := store.Query(EventFilter{})
	queried[0].Data["value"] = "mutated"
	again := store.Query(EventFilter{})
	if again[0].Data["value"] != "original" || again[0].Hash != recorded.Hash {
		t.Fatal("query result mutated stored evidence")
	}
}

func TestIncidentStoreRejectsTraversalID(t *testing.T) {
	store, err := NewIncidentStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(Incident{ID: "../escape", Title: "test"}); err == nil {
		t.Fatal("path-traversal incident ID must be rejected")
	}
}

func TestRedactedSignedBundleVerifies(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "recorder.key")
	publicKey := filepath.Join(dir, "recorder.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Record(Event{SessionID: "s1", Source: "test", Type: "email", Data: map[string]any{"address": "person@example.com"}}); err != nil {
		t.Fatal(err)
	}
	bundle, err := PackageBundle(&Incident{ID: "inc-1", SessionID: "s1", Title: "Redacted"}, store.Query(EventFilter{}), PrivacyProfileConfig{Redact: true}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustJSON(t, bundle)), "person@example.com") {
		t.Fatal("redacted bundle leaked source email")
	}
	if err := VerifyBundle(bundle, publicKey); err != nil {
		t.Fatalf("redacted signed bundle did not verify: %v", err)
	}
	bundle.SignedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := VerifyBundle(bundle, publicKey); err == nil {
		t.Fatal("signed timestamp tampering must fail verification")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSelectIncidentEvents(t *testing.T) {
	events := []Event{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	selected, err := SelectIncidentEvents(&Incident{EventIDs: []string{"b"}}, events)
	if err != nil || len(selected) != 1 || selected[0].ID != "b" {
		t.Fatalf("unexpected selection: %#v, %v", selected, err)
	}
	if _, err := SelectIncidentEvents(&Incident{EventIDs: []string{"missing"}}, events); err == nil {
		t.Fatal("missing referenced evidence must fail closed")
	}
}

func TestVerifyRecorderAuditRejectsUnknownAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Action: "test"}
	entry.Hash = computeRecorderAuditHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	for name, line := range map[string][]byte{
		"unknown":  append(append([]byte{}, data[:len(data)-1]...), []byte(`,"unexpected":true}`)...),
		"trailing": append(append([]byte{}, data...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".jsonl")
			if err := os.WriteFile(path, append(line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecorderAudit(path); err == nil {
				t.Fatal("non-strict audit JSON must be rejected")
			}
		})
	}
}

func TestRecorderAuditWriteFailurePoisonsHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	auditFile = f
	auditRequired.Store(true)
	auditHealthy.Store(true)
	auditLastHash = ""
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		auditFile = nil
		auditRequired.Store(false)
		auditHealthy.Store(false)
		auditLastHash = ""
	})
	if err := writeAudit(AuditEntry{Action: "test"}); err == nil {
		t.Fatal("closed audit file must fail")
	}
	if auditAvailable() {
		t.Fatal("audit failure must poison service health")
	}
}

func TestIncidentStoreReadDirFailureFailsStartup(t *testing.T) {
	original := readIncidentDirectory
	readIncidentDirectory = func(string) ([]os.DirEntry, error) {
		return nil, io.ErrUnexpectedEOF
	}
	t.Cleanup(func() { readIncidentDirectory = original })
	if _, err := NewIncidentStore(t.TempDir()); err == nil {
		t.Fatal("incident directory read failure must prevent startup")
	}
}

func TestRecorderRestartOnlyChangesAreRejected(t *testing.T) {
	base := RecorderPolicy{Version: 1, Recorder: RecorderConfig{
		DataDir:   "/var/lib/secure-ai/incidents",
		Retention: RetentionConfig{MaxSessions: 10},
		Daemon:    DaemonConfig{BindAddr: "127.0.0.1:8495"},
	}}
	for name, mutate := range map[string]func(*RecorderPolicy){
		"data":      func(p *RecorderPolicy) { p.Recorder.DataDir = "/var/lib/secure-ai/other" },
		"retention": func(p *RecorderPolicy) { p.Recorder.Retention.MaxSessions++ },
		"daemon":    func(p *RecorderPolicy) { p.Recorder.Daemon.BindAddr = "127.0.0.1:9495" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if !recorderRestartOnlyChanged(base, candidate) {
				t.Fatal("restart-only change was accepted")
			}
		})
	}
}

func TestCmdIngestPrevalidationRejectsWholeInput(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	policyPath := filepath.Join(dir, "policy.yaml")
	policyYAML := "version: 1\nrecorder:\n  data_dir: " + dataDir + "\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(dir, "input.jsonl")
	input := "{\"timestamp\":\"2026-08-02T00:00:00Z\",\"tool\":\"filesystem.read\",\"allowed\":true}\n{broken\n"
	if err := os.WriteFile(inputPath, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if code := cmdIngest(policyPath, inputPath, "tool-firewall", "ingest-test"); code == 0 {
		t.Fatal("invalid JSONL input must return nonzero")
	}
	if eventStore == nil || eventStore.EventCount() != 0 {
		t.Fatal("prevalidation failure must import zero events")
	}
}
