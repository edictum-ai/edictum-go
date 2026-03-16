package deepcopy

import (
	"reflect"
	"testing"
)

func TestMap_Nil(t *testing.T) {
	if got := Map(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestMap_Shallow(t *testing.T) {
	src := map[string]any{"a": 1, "b": "hello"}
	dst := Map(src)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("expected %v, got %v", src, dst)
	}
	// Mutation of dst must not affect src
	dst["a"] = 999
	if src["a"] == 999 {
		t.Fatal("shallow copy: mutation leaked to source")
	}
}

func TestMap_NestedMap(t *testing.T) {
	inner := map[string]any{"x": 1}
	src := map[string]any{"inner": inner}
	dst := Map(src)

	// Mutate inner map via dst
	dst["inner"].(map[string]any)["x"] = 999
	if inner["x"] == 999 {
		t.Fatal("nested map not deep-copied")
	}
}

func TestMap_NestedSlice(t *testing.T) {
	src := map[string]any{"items": []any{1, 2, 3}}
	dst := Map(src)

	dst["items"].([]any)[0] = 999
	if src["items"].([]any)[0] == 999 {
		t.Fatal("nested slice not deep-copied")
	}
}

func TestSlice_Nil(t *testing.T) {
	if got := Slice(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestSlice_WithMaps(t *testing.T) {
	inner := map[string]any{"k": "v"}
	src := []any{inner, 42}
	dst := Slice(src)

	dst[0].(map[string]any)["k"] = "mutated"
	if inner["k"] == "mutated" {
		t.Fatal("map inside slice not deep-copied")
	}
}

func TestValue_Primitives(t *testing.T) {
	for _, v := range []any{nil, 1, "s", true, 3.14} {
		got := Value(v)
		if got != v {
			t.Fatalf("expected %v, got %v", v, got)
		}
	}
}

func TestMap_DeeplyNested(t *testing.T) {
	src := map[string]any{
		"l1": map[string]any{
			"l2": map[string]any{
				"l3": []any{map[string]any{"deep": true}},
			},
		},
	}
	dst := Map(src)

	// Mutate at depth 3
	dst["l1"].(map[string]any)["l2"].(map[string]any)["l3"].([]any)[0].(map[string]any)["deep"] = false
	original := src["l1"].(map[string]any)["l2"].(map[string]any)["l3"].([]any)[0].(map[string]any)["deep"]
	if original != true {
		t.Fatal("deeply nested mutation leaked")
	}
}
