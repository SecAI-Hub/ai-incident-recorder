package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSensitiveKeysRemoveOpaqueAndNestedCredentialValues(t *testing.T) {
	secrets := []string{"opaque-value-7z", "nested-secret-8x", "array-secret-9y"}
	input := map[string]interface{}{
		"Password": secrets[0],
		"token":    map[string]interface{}{"value": secrets[1]},
		"nested":   []interface{}{map[string]interface{}{"authorization": []interface{}{secrets[2]}}},
	}
	redacted := RedactMap(input, defaultRedactionRules, nil)
	data, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatalf("credential value survived redaction: %s", secret)
		}
	}
	if input["Password"] != secrets[0] {
		t.Fatal("redaction mutated original evidence")
	}
}
