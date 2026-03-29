package workflow

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// MaxDocumentSize is the maximum workflow document size in bytes.
const MaxDocumentSize = 1_048_576

// Load reads and validates a workflow YAML document from disk.
func Load(path string) (Definition, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // Caller-selected path is the API surface.
	if err != nil {
		return Definition{}, fmt.Errorf("workflow: %w", err)
	}
	return parse(raw)
}

// LoadString reads and validates a workflow YAML document from a string.
func LoadString(content string) (Definition, error) {
	return parse([]byte(content))
}

func parse(raw []byte) (Definition, error) {
	if len(raw) > MaxDocumentSize {
		return Definition{}, fmt.Errorf("workflow: document too large (%d bytes, max %d)", len(raw), MaxDocumentSize)
	}

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)

	var def Definition
	if err := dec.Decode(&def); err != nil {
		return Definition{}, fmt.Errorf("workflow: parse error: %w", err)
	}
	var extra any
	err := dec.Decode(&extra)
	if err == nil {
		return Definition{}, fmt.Errorf("workflow: multiple YAML documents are not supported")
	}
	if !errors.Is(err, io.EOF) {
		return Definition{}, fmt.Errorf("workflow: parse error: %w", err)
	}

	if err := def.validate(); err != nil {
		return Definition{}, err
	}
	return def, nil
}
