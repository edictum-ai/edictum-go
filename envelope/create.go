package envelope

import (
	"context"

	"github.com/edictum-ai/edictum-go/internal/deepcopy"
)

// CreateEnvelopeOptions configures envelope creation.
type CreateEnvelopeOptions struct {
	ToolName    string
	Args        map[string]any
	CallID      string
	RunID       string
	CallIndex   int
	ParentCall  string
	Environment string
	Timestamp   string
	Caller      string
	ToolUseID   string
	Principal   *Principal
	Metadata    map[string]any
	Registry    *ToolRegistry
}

// CreateEnvelope creates a new frozen ToolEnvelope.
func CreateEnvelope(_ context.Context, opts CreateEnvelopeOptions) (ToolEnvelope, error) {
	if err := ValidateToolName(opts.ToolName); err != nil {
		return ToolEnvelope{}, err
	}

	// Deep copy args and metadata for immutability
	args := deepcopy.Map(opts.Args)
	metadata := deepcopy.Map(opts.Metadata)

	// Classify side effect
	sideEffect := SideEffectIrreversible
	idempotent := false
	if opts.Registry != nil {
		se, idem := opts.Registry.Classify(opts.ToolName)
		sideEffect = se
		idempotent = idem
	}

	// Extract convenience fields scoped to tool name (parity with Python)
	var bashCmd, filePath string

	switch opts.ToolName {
	case "Bash":
		bashCmd = extractBashCommand(args)
		// BashClassifier always wins over registry for Bash tools
		sideEffect = ClassifyBash(bashCmd)
	case "Read", "Glob", "Grep", "Write", "Edit":
		filePath = extractFilePath(args)
	}

	return ToolEnvelope{
		toolName:    opts.ToolName,
		args:        args,
		callID:      opts.CallID,
		runID:       opts.RunID,
		callIndex:   opts.CallIndex,
		parentCall:  opts.ParentCall,
		sideEffect:  sideEffect,
		idempotent:  idempotent,
		environment: opts.Environment,
		timestamp:   opts.Timestamp,
		caller:      opts.Caller,
		toolUseID:   opts.ToolUseID,
		principal:   opts.Principal,
		bashCommand: bashCmd,
		filePath:    filePath,
		metadata:    metadata,
	}, nil
}

func extractBashCommand(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"bash_command", "bashCommand", "command"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func extractFilePath(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"file_path", "filePath", "path"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
