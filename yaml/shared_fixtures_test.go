package yaml

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yamlv3 "gopkg.in/yaml.v3"
)

// fixtureFile is the top-level structure of a .rejection.yaml file.
type fixtureFile struct {
	Suite    string        `yaml:"suite"`
	Fixtures []fixtureCase `yaml:"fixtures"`
}

// fixtureCase is a single rejection test case.
type fixtureCase struct {
	ID          string        `yaml:"id"`
	Description string        `yaml:"description"`
	Bundle      any           `yaml:"bundle"`
	Expected    fixtureExpect `yaml:"expected"`
}

type fixtureExpect struct {
	Rejected      bool   `yaml:"rejected"`
	ErrorContains string `yaml:"error_contains"`
}

// resolveFixturesDir locates the shared rejection fixtures directory.
// Resolution order:
//  1. EDICTUM_FIXTURES_DIR   — points directly at the rejection fixtures dir
//  2. EDICTUM_SCHEMAS_DIR    — points at the schemas repo root; we append /fixtures/rejection
//  3. fixtures/rejection     — repo-local checkout (e.g. git submodule)
//  4. ../../edictum-schemas/fixtures/rejection — sibling checkout fallback
//
// Returns ("", false) if none found.
func resolveFixturesDir() (string, bool) {
	candidates := []string{}

	if dir := os.Getenv("EDICTUM_FIXTURES_DIR"); dir != "" {
		candidates = append(candidates, dir)
	}
	if dir := os.Getenv("EDICTUM_SCHEMAS_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "fixtures", "rejection"))
	}
	candidates = append(candidates,
		"fixtures/rejection",
		"../../edictum-schemas/fixtures/rejection",
	)

	for _, c := range candidates {
		info, err := os.Stat(c) //nolint:gosec // Test-only: candidates are from known env vars + hardcoded paths.
		if err == nil && info.IsDir() {
			return c, true
		}
	}
	return "", false
}

func loadFixtureSuites(t *testing.T) []fixtureFile {
	t.Helper()
	dir, found := resolveFixturesDir()
	if !found {
		if os.Getenv("EDICTUM_CONFORMANCE_REQUIRED") == "1" {
			t.Fatal("EDICTUM_CONFORMANCE_REQUIRED=1 but shared rejection fixtures not found in any search path")
		}
		t.Skip("shared rejection fixtures not found — skipping (set EDICTUM_FIXTURES_DIR or EDICTUM_SCHEMAS_DIR, or place edictum-schemas as sibling)")
	}
	t.Logf("fixtures resolved at: %s", dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading fixtures dir: %v", err)
	}

	var suites []fixtureFile
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".rejection.yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // Test-only: path from known search candidates + directory listing.
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		var ff fixtureFile
		if err := yamlv3.Unmarshal(raw, &ff); err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		suites = append(suites, ff)
	}
	return suites
}

// loadAndValidateStrict parses YAML and runs the full validation pipeline
// WITHOUT the normalizeLegacyBundle shim, matching canonical Python behaviour.
// The normalizer is a Go-specific compat layer that auto-fills defaults; the
// shared rejection corpus expects strict enforcement of required fields.
func loadAndValidateStrict(bundleYAML string) error {
	var parsed any
	if err := yamlv3.Unmarshal([]byte(bundleYAML), &parsed); err != nil {
		return fmt.Errorf("yaml: parse error: %w", err)
	}
	data, ok := parsed.(map[string]any)
	if !ok {
		return fmt.Errorf("yaml: document must be a mapping")
	}
	// Run the same validation pipeline as parseAndValidate, minus normalization.
	if err := validateSchema(data); err != nil {
		return err
	}
	if err := validateUniqueIDs(data); err != nil {
		return err
	}
	if err := validateRegexes(data); err != nil {
		return err
	}
	if err := validatePreSelectors(data); err != nil {
		return err
	}
	if err := validateSandboxContracts(data); err != nil {
		return err
	}
	return nil
}

func TestSharedRejectionFixtures(t *testing.T) {
	suites := loadFixtureSuites(t)

	for _, ff := range suites {
		t.Run(ff.Suite, func(t *testing.T) {
			for _, fc := range ff.Fixtures {
				t.Run(fc.ID, func(t *testing.T) {
					bundleYAML, err := yamlv3.Marshal(fc.Bundle)
					if err != nil {
						t.Fatalf("re-marshaling bundle for %s: %v", fc.ID, err)
					}

					loadErr := loadAndValidateStrict(string(bundleYAML))

					switch {
					case fc.Expected.Rejected && loadErr == nil:
						t.Errorf("[%s] expected rejection but bundle was accepted\n  description: %s", fc.ID, fc.Description)
					case fc.Expected.Rejected && loadErr != nil:
						if fc.Expected.ErrorContains != "" &&
							!strings.Contains(strings.ToLower(loadErr.Error()), strings.ToLower(fc.Expected.ErrorContains)) {
							t.Errorf("[%s] rejected but error %q does not contain %q\n  description: %s",
								fc.ID, loadErr.Error(), fc.Expected.ErrorContains, fc.Description)
						}
					case !fc.Expected.Rejected && loadErr != nil:
						t.Errorf("[%s] expected acceptance but got error: %v\n  description: %s", fc.ID, loadErr, fc.Description)
					}
				})
			}
		})
	}
}

// TestSharedRejectionFixtures_Discovery ensures the fixture directory
// contains at least one suite file — catches silent path breakage.
func TestSharedRejectionFixtures_Discovery(t *testing.T) {
	suites := loadFixtureSuites(t)
	if len(suites) == 0 {
		t.Fatal("fixture directory exists but contains no .rejection.yaml files")
	}
	t.Logf("discovered %d fixture suites", len(suites))
}

// TestSharedRejectionFixtures_NoDuplicateIDs checks that fixture IDs
// are globally unique across all suite files.
func TestSharedRejectionFixtures_NoDuplicateIDs(t *testing.T) {
	suites := loadFixtureSuites(t)

	seen := map[string]string{} // id -> suite name
	for _, ff := range suites {
		for _, fc := range ff.Fixtures {
			if prev, dup := seen[fc.ID]; dup {
				t.Errorf("duplicate fixture id %q in suite %q (first seen in %q)", fc.ID, ff.Suite, prev)
			}
			seen[fc.ID] = ff.Suite
		}
	}
	t.Logf("checked %d fixture IDs for uniqueness", len(seen))
}

type fixtureResult struct {
	id     string
	desc   string
	pass   bool
	detail string
}

// TestSharedRejectionFixtures_Report runs all fixtures and prints a
// tabulated pass/fail report without failing the test — useful for
// gauging parity progress.
func TestSharedRejectionFixtures_Report(t *testing.T) {
	suites := loadFixtureSuites(t)

	var results []fixtureResult

	for _, ff := range suites {
		for _, fc := range ff.Fixtures {
			bundleYAML, err := yamlv3.Marshal(fc.Bundle)
			if err != nil {
				results = append(results, fixtureResult{
					id: fc.ID, desc: fc.Description, pass: false,
					detail: fmt.Sprintf("marshal error: %v", err),
				})
				continue
			}
			loadErr := loadAndValidateStrict(string(bundleYAML))

			r := fixtureResult{id: fc.ID, desc: fc.Description}
			switch {
			case fc.Expected.Rejected && loadErr == nil:
				r.detail = "expected rejection, got accept"
			case fc.Expected.Rejected && loadErr != nil &&
				fc.Expected.ErrorContains != "" &&
				!strings.Contains(strings.ToLower(loadErr.Error()), strings.ToLower(fc.Expected.ErrorContains)):
				r.detail = fmt.Sprintf("rejected but error %q missing %q", loadErr.Error(), fc.Expected.ErrorContains)
			case fc.Expected.Rejected && loadErr != nil:
				r.pass = true
				r.detail = "correctly rejected"
			case !fc.Expected.Rejected && loadErr != nil:
				r.detail = fmt.Sprintf("expected accept, got: %v", loadErr)
			default:
				r.pass = true
				r.detail = "correctly accepted"
			}
			results = append(results, r)
		}
	}

	var pass, fail int
	for _, r := range results {
		if r.pass {
			pass++
		} else {
			fail++
		}
		status := "PASS"
		if !r.pass {
			status = "FAIL"
		}
		t.Logf("  %s %s: %s — %s", status, r.id, r.desc, r.detail)
	}

	t.Logf("\nParity report: %d/%d pass (%d gaps)", pass, pass+fail, fail)
}
