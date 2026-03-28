package yaml

import (
	"github.com/edictum-ai/edictum-go/rule"
	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/pipeline"
)

// CompiledRuleset is the result of compiling a YAML rule bundle.
type CompiledRuleset struct {
	Preconditions    []rule.Precondition
	Postconditions   []rule.Postcondition
	SessionRules []rule.SessionRule
	SandboxContracts []rule.Precondition
	Limits           pipeline.OperationLimits
	DefaultMode      string
	Tools            map[string]map[string]any
}

// CompileOption configures rule compilation.
type CompileOption func(*compileCtx)

type compileCtx struct {
	customOperators map[string]func(any, any) bool
	customSelectors map[string]func(toolcall.ToolCall) map[string]any
}

// WithCompileOperators sets custom operators for compilation.
func WithCompileOperators(ops map[string]func(any, any) bool) CompileOption {
	return func(c *compileCtx) { c.customOperators = ops }
}

// WithCompileSelectors sets custom selectors for compilation.
func WithCompileSelectors(sels map[string]func(toolcall.ToolCall) map[string]any) CompileOption {
	return func(c *compileCtx) { c.customSelectors = sels }
}

// Compile converts a validated YAML bundle into rule objects.
func Compile(bundle map[string]any, opts ...CompileOption) (CompiledRuleset, error) {
	cc := &compileCtx{}
	for _, opt := range opts {
		opt(cc)
	}

	defaultMode := "enforce"
	if defaults, ok := bundle["defaults"].(map[string]any); ok {
		if m, ok := defaults["mode"].(string); ok {
			defaultMode = m
		}
	}

	result := CompiledRuleset{
		DefaultMode: defaultMode,
		Limits:      pipeline.DefaultLimits(),
	}

	for _, raw := range contractList(bundle) {
		if enabled, ok := raw["enabled"].(bool); ok && !enabled {
			continue
		}
		ctype, _ := raw["type"].(string)
		mode, _ := raw["mode"].(string)
		if mode == "" {
			mode = defaultMode
		}

		switch ctype {
		case "pre":
			pre, err := compilePre(raw, mode, cc)
			if err != nil {
				return CompiledRuleset{}, err
			}
			result.Preconditions = append(result.Preconditions, pre)
		case "post":
			post, err := compilePost(raw, mode, cc)
			if err != nil {
				return CompiledRuleset{}, err
			}
			result.Postconditions = append(result.Postconditions, post)
		case "sandbox":
			// Sandbox rules use within/not_within/allows/not_allows — not
			// when/then — so they go through compileSandbox, not compilePre.
			sb, err := compileSandbox(raw, mode)
			if err != nil {
				return CompiledRuleset{}, err
			}
			result.SandboxContracts = append(result.SandboxContracts, sb)
		case "session":
			isObserve, _ := raw["_observe"].(bool)
			if !isObserve {
				result.Limits = mergeSessionLimits(raw, result.Limits)
			}
			sc := compileSession(raw, mode, result.Limits)
			result.SessionRules = append(result.SessionRules, sc)
		}
	}

	// NOTE: top-level "limits" key is not read here. Limits come exclusively
	// from session rules via mergeSessionLimits, matching Python parity
	// (compiler.py starts from OperationLimits() and only merges per-session).

	if tools, ok := bundle["tools"].(map[string]any); ok {
		result.Tools = make(map[string]map[string]any, len(tools))
		for k, v := range tools {
			if m, ok := v.(map[string]any); ok {
				result.Tools[k] = m
			}
		}
	}

	return result, nil
}
