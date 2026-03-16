package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// MaxBundleSize is the maximum allowed size of a YAML bundle in bytes (1 MB).
const MaxBundleSize = 1_048_576

// BundleHash is a SHA256 hash of raw YAML bytes, used as policy_version.
type BundleHash struct {
	Hex string
}

func (h BundleHash) String() string { return h.Hex }

// LoadBundle loads and validates a YAML contract bundle from a file path.
// Size is checked after reading to avoid TOCTOU races between stat and read.
func LoadBundle(path string) (map[string]any, BundleHash, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // Path is caller-provided; this is the intended API.
	if err != nil {
		return nil, BundleHash{}, fmt.Errorf("yaml: %w", err)
	}
	if len(raw) > MaxBundleSize {
		return nil, BundleHash{}, fmt.Errorf("yaml: bundle file too large (%d bytes, max %d)", len(raw), MaxBundleSize)
	}

	return parseAndValidate(raw)
}

// LoadBundleString loads and validates a YAML contract bundle from a string.
func LoadBundleString(content string) (map[string]any, BundleHash, error) {
	raw := []byte(content)
	if len(raw) > MaxBundleSize {
		return nil, BundleHash{}, fmt.Errorf("yaml: bundle content too large (%d bytes, max %d)", len(raw), MaxBundleSize)
	}
	return parseAndValidate(raw)
}

func computeHash(raw []byte) BundleHash {
	sum := sha256.Sum256(raw)
	return BundleHash{Hex: hex.EncodeToString(sum[:])}
}

func parseAndValidate(raw []byte) (map[string]any, BundleHash, error) {
	hash := computeHash(raw)

	var parsed any
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, BundleHash{}, fmt.Errorf("yaml: parse error: %w", err)
	}

	data, ok := parsed.(map[string]any)
	if !ok {
		return nil, BundleHash{}, fmt.Errorf("yaml: document must be a mapping")
	}

	if err := validateSchema(data); err != nil {
		return nil, BundleHash{}, err
	}
	if err := validateUniqueIDs(data); err != nil {
		return nil, BundleHash{}, err
	}
	if err := validateRegexes(data); err != nil {
		return nil, BundleHash{}, err
	}
	if err := validatePreSelectors(data); err != nil {
		return nil, BundleHash{}, err
	}
	if err := validateSandboxContracts(data); err != nil {
		return nil, BundleHash{}, err
	}

	return data, hash, nil
}
