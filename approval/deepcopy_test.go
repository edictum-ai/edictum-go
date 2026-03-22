package approval

import "testing"

func TestDeepCopyMap_NestedSlice(t *testing.T) {
	src := map[string]any{
		"items": []any{"a", "b", map[string]any{"nested": true}},
	}
	dst := deepCopyMap(src)

	// Mutate source slice element.
	srcItems := src["items"].([]any)
	srcItems[0] = "mutated"
	srcNested := srcItems[2].(map[string]any)
	srcNested["nested"] = false

	dstItems := dst["items"].([]any)
	if dstItems[0] != "a" {
		t.Errorf("slice mutation leaked: got %v, want %q", dstItems[0], "a")
	}
	dstNested := dstItems[2].(map[string]any)
	if dstNested["nested"] != true {
		t.Errorf("nested map mutation leaked: got %v, want true", dstNested["nested"])
	}
}

func TestDeepCopyMap_Nil(t *testing.T) {
	if deepCopyMap(nil) != nil {
		t.Error("deepCopyMap(nil) should return nil")
	}
}

func TestDeepCopyValue_ScalarPassthrough(t *testing.T) {
	if deepCopyValue(42) != 42 {
		t.Error("int passthrough failed")
	}
	if deepCopyValue("hello") != "hello" {
		t.Error("string passthrough failed")
	}
	if deepCopyValue(true) != true {
		t.Error("bool passthrough failed")
	}
	if deepCopyValue(nil) != nil {
		t.Error("nil passthrough failed")
	}
}
