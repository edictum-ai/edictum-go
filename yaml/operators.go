package yaml

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxRegexInput caps regex input to prevent catastrophic backtracking.
const MaxRegexInput = 10_000

// applyOperator applies a single operator to a resolved field value.
func applyOperator(op string, fieldValue any, opValue any, selector string, ec *evalCtx) EvalResult {
	// exists is special: works on missing fields.
	if op == "exists" {
		expected, ok := opValue.(bool)
		if !ok {
			return policyError("exists: operand must be bool")
		}
		isPresent := fieldValue != missing && fieldValue != nil
		if isPresent == expected {
			return pass()
		}
		return fail()
	}

	// All other operators: missing field -> false (contract does not fire).
	if fieldValue == missing || fieldValue == nil {
		return fail()
	}

	// Built-in operators.
	if fn, ok := builtinOperators[op]; ok {
		return fn(fieldValue, opValue, selector)
	}

	// Custom operators.
	if ec != nil && ec.customOperators != nil {
		if fn, ok := ec.customOperators[op]; ok {
			if fn(fieldValue, opValue) {
				return pass()
			}
			return fail()
		}
	}

	return policyError(fmt.Sprintf("Unknown operator: '%s'", op))
}

type operatorFunc func(fieldValue, opValue any, selector string) EvalResult

var builtinOperators = map[string]operatorFunc{
	"equals":       opEquals,
	"not_equals":   opNotEquals,
	"in":           opIn,
	"not_in":       opNotIn,
	"contains":     opContains,
	"contains_any": opContainsAny,
	"starts_with":  opStartsWith,
	"ends_with":    opEndsWith,
	"matches":      opMatches,
	"matches_any":  opMatchesAny,
	"gt":           opGt,
	"gte":          opGte,
	"lt":           opLt,
	"lte":          opLte,
}

func opEquals(fv, ov any, _ string) EvalResult {
	if compareAny(fv, ov) {
		return pass()
	}
	return fail()
}

func opNotEquals(fv, ov any, _ string) EvalResult {
	if !compareAny(fv, ov) {
		return pass()
	}
	return fail()
}

func opIn(fv, ov any, _ string) EvalResult {
	list, ok := toSlice(ov)
	if !ok {
		return policyError("in: expected list operand")
	}
	for _, item := range list {
		if compareAny(fv, item) {
			return pass()
		}
	}
	return fail()
}

func opNotIn(fv, ov any, _ string) EvalResult {
	list, ok := toSlice(ov)
	if !ok {
		return policyError("not_in: expected list operand")
	}
	for _, item := range list {
		if compareAny(fv, item) {
			return fail()
		}
	}
	return pass()
}

func opContains(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("contains", sel, fv)
	}
	sub, ok := ov.(string)
	if !ok {
		return policyError("contains: operand must be string")
	}
	if strings.Contains(s, sub) {
		return pass()
	}
	return fail()
}

func opContainsAny(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("contains_any", sel, fv)
	}
	list, ok := toSlice(ov)
	if !ok {
		return policyError("contains_any: expected list operand")
	}
	for _, item := range list {
		sub, ok := item.(string)
		if !ok {
			return policyError("contains_any: list item must be string")
		}
		if strings.Contains(s, sub) {
			return pass()
		}
	}
	return fail()
}

func opStartsWith(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("starts_with", sel, fv)
	}
	prefix, ok := ov.(string)
	if !ok {
		return policyError("starts_with: operand must be string")
	}
	if strings.HasPrefix(s, prefix) {
		return pass()
	}
	return fail()
}

func opEndsWith(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("ends_with", sel, fv)
	}
	suffix, ok := ov.(string)
	if !ok {
		return policyError("ends_with: operand must be string")
	}
	if strings.HasSuffix(s, suffix) {
		return pass()
	}
	return fail()
}

func opMatches(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("matches", sel, fv)
	}
	truncated := truncateRegexInput(s)
	// Handle pre-compiled *regexp.Regexp (from precompileRegexes) or string.
	re, err := toRegexp(ov)
	if err != nil {
		return policyError(fmt.Sprintf("matches: %s", err))
	}
	if re.MatchString(truncated) {
		return pass()
	}
	return fail()
}

func opMatchesAny(fv, ov any, sel string) EvalResult {
	s, ok := fv.(string)
	if !ok {
		return typeMismatch("matches_any", sel, fv)
	}
	truncated := truncateRegexInput(s)
	list, ok := toSlice(ov)
	if !ok {
		return policyError("matches_any: expected list operand")
	}
	for _, item := range list {
		re, err := toRegexp(item)
		if err != nil {
			return policyError(fmt.Sprintf("matches_any: %s", err))
		}
		if re.MatchString(truncated) {
			return pass()
		}
	}
	return fail()
}

// toRegexp converts a string or *regexp.Regexp to *regexp.Regexp.
func toRegexp(v any) (*regexp.Regexp, error) {
	switch val := v.(type) {
	case *regexp.Regexp:
		return val, nil
	case string:
		return regexp.Compile(val)
	default:
		return nil, fmt.Errorf("invalid regex type %T", v)
	}
}
