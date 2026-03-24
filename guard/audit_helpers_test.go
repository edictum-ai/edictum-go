package guard

import "testing"

func TestDeepCopyRecords_DeepCopiesNestedValues(t *testing.T) {
	original := []map[string]any{{
		"nested": map[string]any{
			"value": "original",
			"list":  []any{map[string]any{"leaf": "kept"}},
		},
	}}

	copied := deepCopyRecords(original)
	copied[0]["nested"].(map[string]any)["value"] = "mutated"
	copied[0]["nested"].(map[string]any)["list"].([]any)[0].(map[string]any)["leaf"] = "changed"

	nested := original[0]["nested"].(map[string]any)
	if got := nested["value"]; got != "original" {
		t.Fatalf("nested map mutated original: got %v", got)
	}
	list := nested["list"].([]any)
	if got := list[0].(map[string]any)["leaf"]; got != "kept" {
		t.Fatalf("nested slice mutated original: got %v", got)
	}
}
