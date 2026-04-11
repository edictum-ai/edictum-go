package yaml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ResolveExtendsFromRegistry resolves the extends: inheritance chain for a
// named ruleset in a registry. Parent rules are prepended before child rules.
// Returns an error on circular references or missing parents.
func ResolveExtendsFromRegistry(rulesets map[string]map[string]any, name string) (map[string]any, error) {
	seen := map[string]bool{}
	var resolve func(n string) (map[string]any, error)
	resolve = func(n string) (map[string]any, error) {
		if seen[n] {
			return nil, fmt.Errorf("yaml: extends: circular reference detected at %q", n)
		}
		bundle, ok := rulesets[n]
		if !ok {
			return nil, fmt.Errorf("yaml: extends: parent ruleset %q not found", n)
		}
		seen[n] = true
		parentName, _ := bundle["extends"].(string)
		if parentName == "" {
			return deepCopyBundle(bundle), nil
		}
		parent, err := resolve(parentName)
		if err != nil {
			return nil, err
		}
		return mergeParentBundle(parent, bundle), nil
	}
	return resolve(name)
}

// mergeParentBundle merges parent rules before child rules.
// Child defaults and metadata override parent values.
func mergeParentBundle(parent, child map[string]any) map[string]any {
	merged := deepCopyBundle(parent)
	parentRules, _ := parent["rules"].([]any)
	childRules, _ := child["rules"].([]any)
	combined := make([]any, 0, len(parentRules)+len(childRules))
	combined = append(combined, parentRules...)
	combined = append(combined, childRules...)
	merged["rules"] = combined
	if defaults, ok := child["defaults"]; ok {
		merged["defaults"] = deepCopyAny(defaults)
	}
	if metadata, ok := child["metadata"]; ok {
		merged["metadata"] = deepCopyAny(metadata)
	}
	delete(merged, "extends")
	return merged
}

func deepCopyBundle(m map[string]any) map[string]any {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = deepCopyAny(v)
	}
	return cp
}

func deepCopyAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyBundle(val)
	case []any:
		cp := make([]any, len(val))
		for i, item := range val {
			cp[i] = deepCopyAny(item)
		}
		return cp
	default:
		return v
	}
}

// MaxBundleSize is the maximum allowed size of a YAML bundle in bytes (1 MB).
const MaxBundleSize = 1_048_576

// BundleHash is a SHA256 hash of raw YAML bytes, used as policy_version.
type BundleHash struct {
	Hex string
}

func (h BundleHash) String() string { return h.Hex }

// LoadBundle loads and validates a YAML rule bundle from a file path.
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

// LoadBundleString loads and validates a YAML rule bundle from a string.
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
	normalizeLegacyBundle(data)

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

func normalizeLegacyBundle(data map[string]any) {
	if _, ok := data["metadata"].(map[string]any); !ok {
		data["metadata"] = map[string]any{"name": "bundle"}
	}
	if _, ok := data["defaults"].(map[string]any); !ok {
		data["defaults"] = map[string]any{"mode": "enforce"}
	}

	rules, _ := data["rules"].([]any)
	for _, raw := range rules {
		contractMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		ctype, _ := contractMap["type"].(string)
		switch ctype {
		case "pre", "post", "session":
			then, _ := contractMap["then"].(map[string]any)
			if then == nil {
				then = map[string]any{}
				contractMap["then"] = then
			}

			if effect, ok := contractMap["action"].(string); ok {
				if _, exists := then["action"]; !exists {
					then["action"] = effect
				}
				delete(contractMap, "action")
			}

			if msg, ok := contractMap["message"].(string); ok {
				if _, exists := then["message"]; !exists {
					then["message"] = msg
				}
				delete(contractMap, "message")
			}

			if timeout, ok := contractMap["timeout"]; ok {
				if _, exists := then["timeout"]; !exists {
					then["timeout"] = timeout
				}
				delete(contractMap, "timeout")
			}

			if timeoutEffect, ok := contractMap["timeout_action"]; ok {
				if _, exists := then["timeout_action"]; !exists {
					then["timeout_action"] = timeoutEffect
				}
				delete(contractMap, "timeout_action")
			}

			if tags, ok := contractMap["tags"]; ok {
				if _, exists := then["tags"]; !exists {
					then["tags"] = tags
				}
				delete(contractMap, "tags")
			}

			if meta, ok := contractMap["then_metadata"]; ok {
				if _, exists := then["metadata"]; !exists {
					then["metadata"] = meta
				}
				delete(contractMap, "then_metadata")
			}

			if _, ok := then["action"]; !ok {
				if ctype == "post" {
					then["action"] = "warn"
				} else {
					then["action"] = "block"
				}
			}
			if _, ok := then["message"]; !ok {
				switch ctype {
				case "session":
					then["message"] = "Session rule violated."
				default:
					then["message"] = "Rule violated."
				}
			}
		case "sandbox":
			if _, ok := contractMap["message"].(string); !ok {
				contractMap["message"] = "Tool call outside sandbox boundary."
			}
		}
	}
}
