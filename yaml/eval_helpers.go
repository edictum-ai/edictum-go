package yaml

import "fmt"

// typeMismatch returns a PolicyError for type mismatches.
func typeMismatch(op, sel string, fv any) EvalResult {
	return policyError(fmt.Sprintf(
		"Type mismatch: operator '%s' cannot be applied to selector '%s' value %T", op, sel, fv))
}

// truncateRegexInput caps input for regex DoS protection.
func truncateRegexInput(s string) string {
	if len(s) > MaxRegexInput {
		return s[:MaxRegexInput]
	}
	return s
}

// toFloat64 converts numeric types to float64.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	}
	return 0, false
}

// toSlice asserts v is []any.
func toSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// compareAny compares two values for equality, handling numeric type coercion.
func compareAny(a, b any) bool {
	if a == b {
		return true
	}
	// Numeric cross-type: int vs float64.
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		return af == bf
	}
	return false
}

// Numeric comparison operators.
func opGt(fv, ov any, sel string) EvalResult  { return numericCmp(fv, ov, sel, "gt", cmpGt) }
func opGte(fv, ov any, sel string) EvalResult { return numericCmp(fv, ov, sel, "gte", cmpGte) }
func opLt(fv, ov any, sel string) EvalResult  { return numericCmp(fv, ov, sel, "lt", cmpLt) }
func opLte(fv, ov any, sel string) EvalResult { return numericCmp(fv, ov, sel, "lte", cmpLte) }

type cmpFunc func(a, b float64) bool

func cmpGt(a, b float64) bool  { return a > b }
func cmpGte(a, b float64) bool { return a >= b }
func cmpLt(a, b float64) bool  { return a < b }
func cmpLte(a, b float64) bool { return a <= b }

func numericCmp(fv, ov any, sel, op string, cmp cmpFunc) EvalResult {
	a, ok := toFloat64(fv)
	if !ok {
		return typeMismatch(op, sel, fv)
	}
	b, ok := toFloat64(ov)
	if !ok {
		return policyError(fmt.Sprintf("%s: operand is not numeric", op))
	}
	if cmp(a, b) {
		return pass()
	}
	return fail()
}
