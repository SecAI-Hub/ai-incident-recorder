package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	auditCheckpointVersion = 1
	auditCheckpointService = "ai-incident-recorder"
	auditCheckpointPayload = "recorder-audit.jsonl"
	maxAuditCheckpointSize = 96 << 20
)

var checkpointHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AuditCheckpoint is a portable, signed envelope around one complete local
// audit chain. Payload is base64-encoded by encoding/json. The signature binds
// its digest and chain summary; verification always recomputes both.
type AuditCheckpoint struct {
	Version       int    `json:"version"`
	Service       string `json:"service"`
	CreatedAt     string `json:"created_at"`
	PayloadName   string `json:"payload_name"`
	Payload       []byte `json:"payload,omitempty"`
	PayloadSize   int64  `json:"payload_size"`
	PayloadSHA256 string `json:"payload_sha256"`
	EntryCount    int    `json:"entry_count"`
	ChainHead     string `json:"chain_head,omitempty"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature,omitempty"`
}

type auditCheckpointSummary struct {
	EntryCount int
	ChainHead  string
	Hashes     map[string]struct{}
}

func summarizeRecorderAuditBytes(data []byte) (auditCheckpointSummary, error) {
	summary := auditCheckpointSummary{Hashes: make(map[string]struct{})}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxAuditLine)
	expectedPrev := ""
	for scanner.Scan() {
		summary.EntryCount++
		var entry AuditEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return auditCheckpointSummary{}, fmt.Errorf("decode audit line %d: %w", summary.EntryCount, err)
		}
		if err := ensureJSONDecoderEOF(decoder); err != nil {
			return auditCheckpointSummary{}, fmt.Errorf("decode audit line %d: %w", summary.EntryCount, err)
		}
		if entry.Action == "" || entry.PrevHash != expectedPrev || entry.Hash != computeRecorderAuditHash(entry) {
			return auditCheckpointSummary{}, fmt.Errorf("audit integrity failure at line %d", summary.EntryCount)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
			return auditCheckpointSummary{}, fmt.Errorf("invalid audit timestamp at line %d", summary.EntryCount)
		}
		expectedPrev = entry.Hash
		summary.Hashes[entry.Hash] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return auditCheckpointSummary{}, fmt.Errorf("scan audit log: %w", err)
	}
	summary.ChainHead = expectedPrev
	return summary, nil
}

func checkpointSignablePayload(checkpoint AuditCheckpoint) ([]byte, error) {
	checkpoint.Payload = nil
	checkpoint.Signature = ""
	return json.Marshal(checkpoint)
}

func exportAuditCheckpoint(sourcePath, keyPath, outputPath string) (AuditCheckpoint, error) {
	data, err := readCheckpointOwnerOnlyFile(sourcePath, maxAuditSize)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read audit source: %w", err)
	}
	summary, err := summarizeRecorderAuditBytes(data)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	keyData, err := readCheckpointOwnerOnlyFile(keyPath, 4096)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read checkpoint signing key: %w", err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		return AuditCheckpoint{}, fmt.Errorf("invalid Ed25519 checkpoint signing key")
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(data)
	checkpoint := AuditCheckpoint{
		Version:       auditCheckpointVersion,
		Service:       auditCheckpointService,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		PayloadName:   auditCheckpointPayload,
		Payload:       data,
		PayloadSize:   int64(len(data)),
		PayloadSHA256: hex.EncodeToString(digest[:]),
		EntryCount:    summary.EntryCount,
		ChainHead:     summary.ChainHead,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
	}
	signable, err := checkpointSignablePayload(checkpoint)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signable))
	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return AuditCheckpoint{}, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxAuditCheckpointSize {
		return AuditCheckpoint{}, fmt.Errorf("checkpoint exceeds %d-byte limit", maxAuditCheckpointSize)
	}
	if err := writeExclusiveDurableFile(outputPath, encoded, 0o600); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("write checkpoint: %w", err)
	}
	return checkpoint, nil
}

func loadAndVerifyAuditCheckpoint(checkpointPath, publicKeyPath, requiredHead string) (AuditCheckpoint, auditCheckpointSummary, error) {
	data, err := readBoundedRegularFile(checkpointPath, maxAuditCheckpointSize)
	if err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("read checkpoint: %w", err)
	}
	var checkpoint AuditCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("decode checkpoint: %w", err)
	}
	if err := ensureJSONDecoderEOF(decoder); err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("decode checkpoint: %w", err)
	}
	if err := validateAuditCheckpointMetadata(checkpoint); err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, err
	}
	digest := sha256.Sum256(checkpoint.Payload)
	if checkpoint.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("checkpoint payload digest mismatch")
	}
	summary, err := summarizeRecorderAuditBytes(checkpoint.Payload)
	if err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, err
	}
	if checkpoint.EntryCount != summary.EntryCount || checkpoint.ChainHead != summary.ChainHead {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("checkpoint chain summary mismatch")
	}
	if requiredHead != "" {
		if !checkpointHashPattern.MatchString(requiredHead) {
			return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("required head must be a lowercase SHA-256 digest")
		}
		if _, ok := summary.Hashes[requiredHead]; !ok {
			return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("checkpoint does not contain required anchored head")
		}
	}
	publicData, err := readCheckpointPublicKeyFile(publicKeyPath, 4096)
	if err != nil {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("read trusted public key: %w", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicData)))
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("invalid trusted Ed25519 public key")
	}
	if checkpoint.PublicKey != base64.StdEncoding.EncodeToString(publicBytes) {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("checkpoint public key does not match trusted key")
	}
	signature, err := base64.StdEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("invalid checkpoint signature")
	}
	signable, err := checkpointSignablePayload(checkpoint)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicBytes), signable, signature) {
		return AuditCheckpoint{}, auditCheckpointSummary{}, fmt.Errorf("checkpoint signature verification failed")
	}
	return checkpoint, summary, nil
}

func validateAuditCheckpointMetadata(checkpoint AuditCheckpoint) error {
	if int64(len(checkpoint.Payload)) > maxAuditSize {
		return fmt.Errorf("checkpoint payload exceeds %d-byte audit log limit", maxAuditSize)
	}
	if checkpoint.Version != auditCheckpointVersion || checkpoint.Service != auditCheckpointService ||
		checkpoint.PayloadName != auditCheckpointPayload || checkpoint.PayloadSize != int64(len(checkpoint.Payload)) ||
		!checkpointHashPattern.MatchString(checkpoint.PayloadSHA256) || checkpoint.EntryCount < 0 {
		return fmt.Errorf("invalid checkpoint metadata")
	}
	if _, err := time.Parse(time.RFC3339Nano, checkpoint.CreatedAt); err != nil {
		return fmt.Errorf("invalid checkpoint timestamp")
	}
	return nil
}

func recoverAuditCheckpoint(checkpointPath, publicKeyPath, outputPath, requiredHead string) error {
	if requiredHead == "" {
		return fmt.Errorf("recovery requires an independently retained chain head")
	}
	checkpoint, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, publicKeyPath, requiredHead)
	if err != nil {
		return err
	}
	if err := writeExclusiveDurableFile(outputPath, checkpoint.Payload, 0o600); err != nil {
		return fmt.Errorf("write recovered audit log: %w", err)
	}
	return nil
}

func readCheckpointOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	return readCheckpointTrustedFile(path, limit, 0o077)
}

func readCheckpointPublicKeyFile(path string, limit int64) ([]byte, error) {
	return readCheckpointTrustedFile(path, limit, 0o022)
}

func readCheckpointTrustedFile(path string, limit int64, forbiddenMode os.FileMode) ([]byte, error) {
	if path == "" || limit < 0 {
		return nil, fmt.Errorf("checkpoint key/source path or limit is invalid")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("checkpoint key/source path must be canonical and absolute")
	}
	absPath := path
	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirInfo.Mode().Perm()&0o022 != 0 || !checkpointTrustedOwner(dirInfo) {
		return nil, fmt.Errorf("checkpoint key/source directory ownership or permissions are unsafe")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedDir, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, openedDir) {
		return nil, fmt.Errorf("checkpoint key/source directory changed while opening")
	}
	name := filepath.Base(absPath)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&forbiddenMode != 0 || !checkpointTrustedOwner(before) ||
		before.Size() < 0 || before.Size() > limit {
		return nil, fmt.Errorf("checkpoint key/source file ownership or permissions are unsafe")
	}
	// #nosec G304,G703 -- name is a basename opened relative to an identity-checked root; O_NOFOLLOW and opened-file identity checks prevent substitution.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("checkpoint key/source file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("checkpoint key/source file exceeds its read limit")
	}
	afterRead, err := f.Stat()
	if err != nil || !os.SameFile(opened, afterRead) || afterRead.Size() != int64(len(data)) {
		return nil, fmt.Errorf("checkpoint key/source file changed while reading")
	}
	afterPath, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, afterPath) || afterPath.Mode().Perm()&forbiddenMode != 0 ||
		!checkpointTrustedOwner(afterPath) {
		return nil, fmt.Errorf("checkpoint key/source file changed while validating trust")
	}
	currentDir, err := os.Lstat(dir)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return nil, fmt.Errorf("checkpoint key/source directory changed while validating trust")
	}
	return data, nil
}

func checkpointTrustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	euid := int64(os.Geteuid())
	return stat.Uid == 0 || (euid >= 0 && int64(stat.Uid) == euid)
}

type checkpointFileWriter func(*os.File, []byte) error

func writeExclusiveDurableFile(path string, data []byte, mode os.FileMode) error {
	return writeExclusiveDurableFileWithWriter(path, data, mode, func(file *os.File, content []byte) error {
		written, err := file.Write(content)
		if err == nil && written != len(content) {
			err = io.ErrShortWrite
		}
		return err
	})
}

func writeExclusiveDurableFileWithWriter(path string, data []byte, mode os.FileMode, writeData checkpointFileWriter) (returnErr error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("output path must be canonical and absolute")
	}
	if writeData == nil {
		return fmt.Errorf("output writer is unavailable")
	}
	absPath := path
	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirInfo.Mode().Perm()&0o022 != 0 || !checkpointTrustedOwner(dirInfo) {
		return fmt.Errorf("output directory must be trusted and not group/world-writable")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	openedDir, err := root.Stat(".")
	if err != nil || !os.SameFile(dirInfo, openedDir) {
		return fmt.Errorf("output directory changed while opening")
	}
	name := filepath.Base(absPath)
	tempName, f, err := createCheckpointTemp(root, mode)
	if err != nil {
		return err
	}
	tempPresent := true
	finalLinked := false
	published := false
	defer func() {
		if published {
			return
		}
		var cleanupErr error
		if finalLinked {
			if err := root.Remove(name); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove failed final output: %w", err))
			}
		}
		if tempPresent {
			if err := root.Remove(tempName); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove temporary output: %w", err))
			}
		}
		if err := syncCheckpointDirectory(root, dirInfo); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("sync output cleanup: %w", err))
		}
		returnErr = errors.Join(returnErr, cleanupErr)
	}()
	closed := false
	defer func() {
		if !closed {
			if closeErr := f.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, closeErr)
			}
		}
	}()
	if err := writeData(f, data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	if err := root.Link(tempName, name); err != nil {
		return fmt.Errorf("publish output without replacement: %w", err)
	}
	finalLinked = true
	if err := root.Remove(tempName); err != nil {
		return fmt.Errorf("remove published temporary link: %w", err)
	}
	tempPresent = false
	if err := syncCheckpointDirectory(root, dirInfo); err != nil {
		return err
	}
	currentDir, err := os.Lstat(dir)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return fmt.Errorf("output directory moved during publication")
	}
	published = true
	return nil
}

func createCheckpointTemp(root *os.Root, mode os.FileMode) (string, *os.File, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".secai-checkpoint-" + hex.EncodeToString(random[:]) + ".tmp"
		// #nosec G304,G703 -- the random basename is created beneath an identity-checked Root and O_EXCL prevents collision replacement.
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if os.IsExist(err) {
			continue
		}
		return name, file, err
	}
	return "", nil, fmt.Errorf("could not allocate unique checkpoint temporary file")
}

func syncCheckpointDirectory(root *os.Root, expected os.FileInfo) error {
	dirHandle, err := root.Open(".")
	if err != nil {
		return err
	}
	opened, statErr := dirHandle.Stat()
	if statErr != nil || !os.SameFile(expected, opened) {
		_ = dirHandle.Close()
		return fmt.Errorf("output directory changed during publication")
	}
	syncErr := dirHandle.Sync()
	closeErr := dirHandle.Close()
	return errors.Join(syncErr, closeErr)
}

func cmdAuditCheckpoint(sourcePath, keyPath, outputPath string) int {
	checkpoint, err := exportAuditCheckpoint(sourcePath, keyPath, outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint export failed: %v\n", err)
		return 1
	}
	fmt.Printf("audit checkpoint written: entries=%d head=%s\n", checkpoint.EntryCount, checkpoint.ChainHead)
	return 0
}

func cmdAuditVerify(checkpointPath, publicKeyPath, requiredHead string) int {
	checkpoint, _, err := loadAndVerifyAuditCheckpoint(checkpointPath, publicKeyPath, requiredHead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint verification failed: %v\n", err)
		return 1
	}
	fmt.Printf("audit checkpoint verified: entries=%d head=%s\n", checkpoint.EntryCount, checkpoint.ChainHead)
	return 0
}

func cmdAuditRecover(checkpointPath, publicKeyPath, outputPath, requiredHead string) int {
	if err := recoverAuditCheckpoint(checkpointPath, publicKeyPath, outputPath, requiredHead); err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint recovery failed: %v\n", err)
		return 1
	}
	fmt.Printf("verified audit log recovered to new path %s\n", outputPath)
	return 0
}
