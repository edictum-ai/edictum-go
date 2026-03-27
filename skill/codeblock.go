package skill

import (
	"regexp"
	"strings"
)

// codeBlockRe matches fenced code blocks in markdown. Group 1 is the
// optional language tag, group 2 is the code content.
var codeBlockRe = regexp.MustCompile("(?ms)^```(\\w*)\\s*\\n(.*?)^```")

// codeBlock represents a parsed markdown fenced code block with its
// position in the original file.
type codeBlock struct {
	Language  string
	Content   string
	StartLine int // 1-based line number in the original file
}

// extractCodeBlocks parses all fenced code blocks from markdown content,
// tracking line numbers. A maximum of 50 code blocks are extracted.
func extractCodeBlocks(content string) []codeBlock {
	const maxBlocks = 50

	matches := codeBlockRe.FindAllStringSubmatchIndex(content, -1)
	blocks := make([]codeBlock, 0, len(matches))

	for i, loc := range matches {
		if i >= maxBlocks {
			break
		}

		// loc indices: [full_start, full_end, lang_start, lang_end, code_start, code_end]
		langStart, langEnd := loc[2], loc[3]
		codeStart, codeEnd := loc[4], loc[5]

		lang := ""
		if langStart >= 0 && langEnd >= 0 {
			lang = content[langStart:langEnd]
		}

		code := ""
		if codeStart >= 0 && codeEnd >= 0 {
			code = content[codeStart:codeEnd]
		}

		// Calculate 1-based line number of the opening ```
		startLine := strings.Count(content[:loc[0]], "\n") + 1

		blocks = append(blocks, codeBlock{
			Language:  lang,
			Content:   code,
			StartLine: startLine,
		})
	}

	return blocks
}
