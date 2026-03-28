package yaml

import (
	"fmt"
	"regexp"

	"github.com/edictum-ai/edictum-go/toolcall"
	"github.com/edictum-ai/edictum-go/redaction"
)

var (
	placeholderRe          = regexp.MustCompile(`\{([^}]+)\}`)
	placeholderCap         = 200
	messageRedactionPolicy = redaction.NewPolicy()
)

func expandMessage(
	template string,
	env toolcall.ToolCall,
	outputText string,
	customSelectors map[string]func(toolcall.ToolCall) map[string]any,
	outputPresent bool,
) string {
	return placeholderRe.ReplaceAllStringFunc(template, func(match string) string {
		submatches := placeholderRe.FindStringSubmatch(match)
		if len(submatches) != 2 {
			return match
		}

		var opts []EvalOption
		if customSelectors != nil {
			opts = append(opts, WithCustomSelectors(customSelectors))
		}
		opts = append(opts, withOutputPresent(outputPresent))

		ec := evalCtx{}
		for _, opt := range opts {
			opt(&ec)
		}

		value := resolveSelector(submatches[1], env, outputText, &ec)
		if value == missing || value == nil {
			return match
		}

		text := fmt.Sprint(value)
		if messageRedactionPolicy.DetectSecretValue(text) {
			text = "[REDACTED]"
		}
		if len(text) > placeholderCap {
			text = text[:placeholderCap-3] + "..."
		}
		return text
	})
}
