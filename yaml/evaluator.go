// Package yaml provides YAML contract bundle loading and compilation.
package yaml

import (
	"fmt"

	"github.com/edictum-ai/edictum-go/envelope"
)

// EvalResult represents the outcome of expression evaluation.
// Pass = condition matched (true), Fail = did not match (false),
// PolicyError = type mismatch/error (triggers fail-closed).
type EvalResult struct {
	Matched     bool
	PolicyError bool
	ErrorMsg    string
}

// pass returns a matched result.
func pass() EvalResult { return EvalResult{Matched: true} }

// fail returns a non-matched result.
func fail() EvalResult { return EvalResult{} }

// policyError returns a policy error result (fail-closed: Matched=true).
func policyError(msg string) EvalResult {
	return EvalResult{Matched: true, PolicyError: true, ErrorMsg: msg}
}

// EvalOption configures expression evaluation.
type EvalOption func(*evalCtx)

type evalCtx struct {
	customOperators map[string]func(any, any) bool
	customSelectors map[string]func(envelope.ToolEnvelope) map[string]any
}

// WithCustomOperators registers custom operator functions.
func WithCustomOperators(ops map[string]func(any, any) bool) EvalOption {
	return func(ctx *evalCtx) { ctx.customOperators = ops }
}

// WithCustomSelectors registers custom selector prefix resolvers.
func WithCustomSelectors(sels map[string]func(envelope.ToolEnvelope) map[string]any) EvalOption {
	return func(ctx *evalCtx) { ctx.customSelectors = sels }
}

// EvaluateExpression evaluates a boolean expression tree against an envelope.
func EvaluateExpression(expr map[string]any, env envelope.ToolEnvelope, outputText string, opts ...EvalOption) EvalResult {
	var ec evalCtx
	for _, o := range opts {
		o(&ec)
	}
	return evalExpr(expr, env, outputText, &ec)
}

func evalExpr(expr map[string]any, env envelope.ToolEnvelope, outputText string, ec *evalCtx) EvalResult {
	if v, ok := expr["all"]; ok {
		items, _ := v.([]any)
		return evalAll(items, env, outputText, ec)
	}
	if v, ok := expr["any"]; ok {
		items, _ := v.([]any)
		return evalAny(items, env, outputText, ec)
	}
	if v, ok := expr["not"]; ok {
		inner, _ := v.(map[string]any)
		return evalNot(inner, env, outputText, ec)
	}
	return evalLeaf(expr, env, outputText, ec)
}

// evalAll implements short-circuit AND. PolicyError propagates immediately.
func evalAll(exprs []any, env envelope.ToolEnvelope, outputText string, ec *evalCtx) EvalResult {
	for _, item := range exprs {
		m, ok := item.(map[string]any)
		if !ok {
			return policyError("all: child is not a map")
		}
		r := evalExpr(m, env, outputText, ec)
		if r.PolicyError {
			return r
		}
		if !r.Matched {
			return fail()
		}
	}
	return pass()
}

// evalAny implements short-circuit OR. PolicyError propagates immediately.
func evalAny(exprs []any, env envelope.ToolEnvelope, outputText string, ec *evalCtx) EvalResult {
	for _, item := range exprs {
		m, ok := item.(map[string]any)
		if !ok {
			return policyError("any: child is not a map")
		}
		r := evalExpr(m, env, outputText, ec)
		if r.PolicyError {
			return r
		}
		if r.Matched {
			return pass()
		}
	}
	return fail()
}

// evalNot inverts the result. PolicyError propagates.
func evalNot(expr map[string]any, env envelope.ToolEnvelope, outputText string, ec *evalCtx) EvalResult {
	r := evalExpr(expr, env, outputText, ec)
	if r.PolicyError {
		return r
	}
	if r.Matched {
		return fail()
	}
	return pass()
}

// evalLeaf evaluates a leaf node: one selector key mapping to one operator block.
func evalLeaf(leaf map[string]any, env envelope.ToolEnvelope, outputText string, ec *evalCtx) EvalResult {
	if len(leaf) != 1 {
		return policyError(fmt.Sprintf("leaf expression must have exactly 1 selector, got %d", len(leaf)))
	}
	// Extract the single selector key.
	var selector string
	var operatorBlock any
	for k, v := range leaf {
		selector = k
		operatorBlock = v
		break
	}

	fieldValue := resolveSelector(selector, env, outputText, ec)

	block, ok := operatorBlock.(map[string]any)
	if !ok {
		return policyError("operator block is not a map")
	}

	// Extract the single operator.
	var opName string
	var opValue any
	for k, v := range block {
		opName = k
		opValue = v
		break
	}

	return applyOperator(opName, fieldValue, opValue, selector, ec)
}
