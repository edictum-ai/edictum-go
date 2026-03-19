// Package shlex provides shell-aware tokenization for sandbox contract
// evaluation. Security-critical: used to extract paths and commands
// from shell command strings for sandbox enforcement.
//
// Matches Python shlex.split() behavior: handles single and double
// quotes, backslash escapes. Falls back to basic split with quote
// stripping on unclosed quotes (fail-closed).
package shlex

import "strings"

// Split splits a command string into tokens using shell-like syntax.
// Handles single quotes, double quotes, and backslash escapes.
// On unclosed quotes, falls back to whitespace split with quote
// stripping (fail-closed: paths are still extracted).
func Split(s string) ([]string, error) {
	tokens, err := splitShell(s)
	if err != nil {
		return fallbackSplit(s), err
	}
	return tokens, nil
}

// MustSplit is like Split but discards the error (uses fallback).
func MustSplit(s string) []string {
	tokens, _ := Split(s)
	return tokens
}

func splitShell(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inToken := false

	runes := []rune(s)
	i := 0
	for i < len(runes) {
		ch := runes[i]

		switch {
		case ch == '\\' && i+1 < len(runes):
			inToken = true
			i++
			current.WriteRune(runes[i])

		case ch == '\'':
			inToken = true
			i++
			for i < len(runes) && runes[i] != '\'' {
				current.WriteRune(runes[i])
				i++
			}
			if i >= len(runes) {
				return nil, &UnclosedQuoteError{Quote: '\''}
			}

		case ch == '"':
			inToken = true
			i++
			for i < len(runes) && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
					current.WriteRune(runes[i])
				} else {
					current.WriteRune(runes[i])
				}
				i++
			}
			if i >= len(runes) {
				return nil, &UnclosedQuoteError{Quote: '"'}
			}

		case ch == ' ' || ch == '\t':
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}

		default:
			inToken = true
			current.WriteRune(ch)
		}

		i++
	}

	if inToken {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

func fallbackSplit(s string) []string {
	fields := strings.Fields(s)
	tokens := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "'\"")
		if f != "" {
			tokens = append(tokens, f)
		}
	}
	return tokens
}

// UnclosedQuoteError indicates the input has an unclosed quote.
type UnclosedQuoteError struct {
	Quote rune
}

func (e *UnclosedQuoteError) Error() string {
	return "unclosed quote: " + string(e.Quote)
}
