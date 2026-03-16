package guard

import "strings"

// defaultSuccessCheck implements the default heuristic for tool success
// detection. Matches the Python heuristic exactly:
//   - nil -> true
//   - map with is_error -> false
//   - string starting with "error:" or "fatal:" -> false
//   - else -> true
func defaultSuccessCheck(_ string, result any) bool {
	if result == nil {
		return true
	}
	if m, ok := result.(map[string]any); ok {
		if isErr, exists := m["is_error"]; exists {
			if b, ok := isErr.(bool); ok && b {
				return false
			}
		}
	}
	if s, ok := result.(string); ok {
		// Match Python: check first 7 chars lowercased
		prefix := s
		if len(prefix) > 7 {
			prefix = prefix[:7]
		}
		lower := strings.ToLower(prefix)
		if strings.HasPrefix(lower, "error:") || strings.HasPrefix(lower, "fatal:") {
			return false
		}
	}
	return true
}
