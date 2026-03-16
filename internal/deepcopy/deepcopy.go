// Package deepcopy provides utilities for deep copying Go values.
// Used by envelope creation and guard reload to ensure immutability.
package deepcopy

// Map returns a deep copy of a map[string]any. Nested maps and slices
// are recursively copied. Non-container values are copied by value.
// Returns nil for nil input.
func Map(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = Value(v)
	}
	return dst
}

// Slice returns a deep copy of a []any. Nested maps and slices
// are recursively copied.
func Slice(src []any) []any {
	if src == nil {
		return nil
	}
	dst := make([]any, len(src))
	for i, v := range src {
		dst[i] = Value(v)
	}
	return dst
}

// Value deep-copies a single value. Maps and slices are recursively
// copied; all other types are returned as-is (primitives are safe,
// pointers to immutable types are safe by convention).
func Value(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return Map(val)
	case []any:
		return Slice(val)
	case map[any]any:
		dst := make(map[any]any, len(val))
		for k, v2 := range val {
			dst[k] = Value(v2)
		}
		return dst
	default:
		return v
	}
}
