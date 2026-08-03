package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func nonCanonicalCheckpointPath(path string) string {
	separator := string(os.PathSeparator)
	return filepath.Dir(path) + separator + "." + separator + filepath.Base(path)
}

func recorderAuditFixture(t *testing.T, path string, actions ...string) ([]byte, []string) {
	t.Helper()
	previous := ""
	var payload []byte
	hashes := make([]string, 0, len(actions))
	for i, action := range actions {
		entry := AuditEntry{
			Timestamp: time.Date(2026, time.August, 2, 12, 0, i, 0, time.UTC).Format(time.RFC3339Nano),
			Action:    action,
			PrevHash:  previous,
		}
		entry.Hash = computeRecorderAuditHash(entry)
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, encoded...)
		payload = append(payload, '\n')
		previous = entry.Hash
		hashes = append(hashes, entry.Hash)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return payload, hashes
}

func TestAuditCheckpointExportVerifyAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "checkpoint.key")
	publicKey := filepath.Join(dir, "checkpoint.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	auditSource := filepath.Join(dir, "recorder-audit.jsonl")
	_, hashes := recorderAuditFixture(t, auditSource, "daemon.started", "event.recorded")
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	for _, testCase := range []struct {
		name      string
		path      string
		publicKey bool
	}{
		{name: "relative source", path: filepath.Base(auditSource)},
		{name: "noncanonical source", path: nonCanonicalCheckpointPath(auditSource)},
		{name: "relative private key", path: filepath.Base(privateKey)},
		{name: "noncanonical private key", path: nonCanonicalCheckpointPath(privateKey)},
		{name: "relative public key", path: filepath.Base(publicKey), publicKey: true},
		{name: "noncanonical public key", path: nonCanonicalCheckpointPath(publicKey), publicKey: true},
	} {
		var err error
		if testCase.publicKey {
			_, err = readCheckpointPublicKeyFile(testCase.path, 4096)
		} else {
			_, err = readCheckpointOwnerOnlyFile(testCase.path, maxAuditSize)
		}
		if err == nil {
			t.Fatalf("%s must be rejected", testCase.name)
		}
	}

	checkpoint, err := exportAuditCheckpoint(auditSource, privateKey, checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(checkpointPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint must be owner-only: info=%v err=%v", info, err)
	}
	if checkpoint.EntryCount != 2 || checkpoint.ChainHead != hashes[1] {
		t.Fatalf("unexpected checkpoint summary: %#v", checkpoint)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, publicKey, hashes[0]); err != nil {
		t.Fatalf("verify checkpoint containing retained anchor: %v", err)
	}
	otherPrivateKey := filepath.Join(dir, "other-checkpoint.key")
	otherPublicKey := filepath.Join(dir, "other-checkpoint.pub")
	if err := generateKeypair(otherPrivateKey, otherPublicKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, otherPublicKey, ""); err == nil {
		t.Fatal("checkpoint must not trust its embedded public key")
	}
	if err := os.Chmod(publicKey, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, publicKey, ""); err == nil {
		t.Fatal("group/world-writable trusted public key must be rejected")
	}
	if err := os.Chmod(publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	publicLink := filepath.Join(dir, "checkpoint-link.pub")
	if err := os.Symlink(publicKey, publicLink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, publicLink, ""); err == nil {
		t.Fatal("symlinked trusted public key must be rejected")
	}
	unsafeTrustDir := filepath.Join(dir, "unsafe-trust")
	if err := os.Mkdir(unsafeTrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeTrustDir, 0o777); err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	unsafePublicKey := filepath.Join(unsafeTrustDir, "checkpoint.pub")
	if err := os.WriteFile(unsafePublicKey, publicBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, unsafePublicKey, ""); err == nil {
		t.Fatal("trusted public key in a group/world-writable directory must be rejected")
	}
	if err := os.Chmod(privateKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exportAuditCheckpoint(auditSource, privateKey, filepath.Join(dir, "unsafe-key-checkpoint.json")); err == nil {
		t.Fatal("non-owner-only checkpoint private key must be rejected")
	}
	if err := os.Chmod(privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeDir := filepath.Join(dir, "unsafe-output")
	if err := os.Mkdir(unsafeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := exportAuditCheckpoint(auditSource, privateKey, filepath.Join(unsafeDir, "checkpoint.json")); err == nil {
		t.Fatal("checkpoint export into a group/world-writable directory must fail")
	}
	if _, err := exportAuditCheckpoint(auditSource, privateKey, checkpointPath); err == nil {
		t.Fatal("checkpoint export must not overwrite an existing file")
	}

	encoded, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	var tampered AuditCheckpoint
	if err := json.Unmarshal(encoded, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Payload[0] ^= 1
	tamperedBytes, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tamperedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndVerifyAuditCheckpoint(tamperedPath, publicKey, ""); err == nil {
		t.Fatal("tampered checkpoint payload must fail verification")
	}
}

func TestAuditCheckpointRejectsPayloadAboveRuntimeLimit(t *testing.T) {
	checkpoint := AuditCheckpoint{Payload: make([]byte, maxAuditSize+1)}
	if err := validateAuditCheckpointMetadata(checkpoint); err == nil {
		t.Fatal("decoded payload above the runtime audit-log limit must be rejected")
	}
}

func TestAuditCheckpointPublicationCleansPartialTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "checkpoint.json")
	content := []byte("complete checkpoint")
	injectedFailure := errors.New("injected write failure")
	err := writeExclusiveDurableFileWithWriter(output, content, 0o600, func(file *os.File, data []byte) error {
		if _, err := file.Write(data[:1]); err != nil {
			return err
		}
		return injectedFailure
	})
	if err == nil {
		t.Fatal("injected partial write must fail")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed publication left a final output: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed publication left temporary entries: %v", entries)
	}
	if err := writeExclusiveDurableFile(output, content, 0o600); err != nil {
		t.Fatalf("retry after cleanup failed: %v", err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || string(actual) != string(content) {
		t.Fatalf("published bytes differ: %q err=%v", actual, err)
	}
	if err := writeExclusiveDurableFile("relative-checkpoint.json", content, 0o600); err == nil {
		t.Fatal("relative checkpoint output must be rejected")
	}
	if err := writeExclusiveDurableFile(nonCanonicalCheckpointPath(filepath.Join(dir, "other.json")), content, 0o600); err == nil {
		t.Fatal("noncanonical checkpoint output must be rejected")
	}
}

func TestAuditCheckpointRecoveryRequiresIndependentAnchorAndNewPath(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "checkpoint.key")
	publicKey := filepath.Join(dir, "checkpoint.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	auditSource := filepath.Join(dir, "recorder-audit.jsonl")
	payload, hashes := recorderAuditFixture(t, auditSource, "daemon.started", "policy.reloaded")
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	if _, err := exportAuditCheckpoint(auditSource, privateKey, checkpointPath); err != nil {
		t.Fatal(err)
	}

	recovered := filepath.Join(dir, "recovered-audit.jsonl")
	if err := recoverAuditCheckpoint(checkpointPath, publicKey, recovered, ""); err == nil {
		t.Fatal("recovery without an independent anchor must fail")
	}
	if err := recoverAuditCheckpoint(checkpointPath, publicKey, recovered, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("recovery with an absent anchor must fail")
	}
	if err := recoverAuditCheckpoint(checkpointPath, publicKey, recovered, hashes[1]); err != nil {
		t.Fatal(err)
	}
	recoveredBytes, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if string(recoveredBytes) != string(payload) {
		t.Fatal("recovered audit bytes differ from signed checkpoint payload")
	}
	if info, err := os.Stat(recovered); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovered audit log must be owner-only: info=%v err=%v", info, err)
	}
	if err := recoverAuditCheckpoint(checkpointPath, publicKey, recovered, hashes[1]); err == nil {
		t.Fatal("recovery must not overwrite an existing destination")
	}
}
