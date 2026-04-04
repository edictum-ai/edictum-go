// Package workflow implements M1 workflow gate loading, state, and runtime evaluation.
package workflow

import (
	"fmt"
	"regexp"

	"github.com/edictum-ai/edictum-go/toolcall"
)

var workflowNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Definition is a validated workflow document.
type Definition struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   Metadata       `yaml:"metadata"`
	Stages     []Stage        `yaml:"stages"`
	index      map[string]int `yaml:"-"`
}

// Metadata identifies a workflow document.
type Metadata struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Stage is one linear workflow stage.
type Stage struct {
	ID          string    `yaml:"id"`
	Description string    `yaml:"description,omitempty"`
	Entry       []Gate    `yaml:"entry,omitempty"`
	Tools       []string  `yaml:"tools,omitempty"`
	Checks      []Check   `yaml:"checks,omitempty"`
	Exit        []Gate    `yaml:"exit,omitempty"`
	Approval    *Approval `yaml:"approval,omitempty"`
}

// Gate is a declarative workflow fact check.
type Gate struct {
	Condition string `yaml:"condition"`
	Message   string `yaml:"message,omitempty"`
}

// Approval is a stage-boundary approval requirement.
type Approval struct {
	Message string `yaml:"message"`
}

// Check constrains a call while a stage is active.
type Check struct {
	CommandMatches    string         `yaml:"command_matches,omitempty"`
	CommandNotMatches string         `yaml:"command_not_matches,omitempty"`
	Message           string         `yaml:"message,omitempty"`
	commandMatchesRE  *regexp.Regexp `yaml:"-"`
	commandNotRE      *regexp.Regexp `yaml:"-"`
}

func (d *Definition) validate() error {
	if d.APIVersion != "edictum/v1" {
		return fmt.Errorf("workflow: apiVersion must be %q", "edictum/v1")
	}
	if d.Kind != "Workflow" {
		return fmt.Errorf("workflow: kind must be %q", "Workflow")
	}
	if !workflowNameRe.MatchString(d.Metadata.Name) {
		return fmt.Errorf("workflow: metadata.name must match %q", workflowNameRe.String())
	}
	if len(d.Stages) == 0 {
		return fmt.Errorf("workflow: stages must contain at least one item")
	}

	d.index = make(map[string]int, len(d.Stages))
	for i := range d.Stages {
		stage := &d.Stages[i]
		if err := validateStage(stage); err != nil {
			return err
		}
		if _, exists := d.index[stage.ID]; exists {
			return fmt.Errorf("workflow: duplicate stage id %q", stage.ID)
		}
		d.index[stage.ID] = i
	}
	return nil
}

func validateStage(stage *Stage) error {
	if !workflowNameRe.MatchString(stage.ID) {
		return fmt.Errorf("workflow: stage.id %q must match %q", stage.ID, workflowNameRe.String())
	}
	for _, tool := range stage.Tools {
		if err := toolcall.ValidateToolName(tool); err != nil {
			return fmt.Errorf("workflow: invalid tool %q in stage %q: %w", tool, stage.ID, err)
		}
	}
	for _, gate := range append(append([]Gate{}, stage.Entry...), stage.Exit...) {
		if gate.Condition == "" {
			return fmt.Errorf("workflow: stage %q gate condition must not be empty", stage.ID)
		}
		if _, err := parseCondition(gate.Condition); err != nil {
			return fmt.Errorf("workflow: stage %q invalid gate condition %q: %w", stage.ID, gate.Condition, err)
		}
	}
	for i := range stage.Checks {
		check := &stage.Checks[i]
		if (check.CommandMatches == "") == (check.CommandNotMatches == "") {
			return fmt.Errorf("workflow: stage %q checks must set exactly one of command_matches or command_not_matches", stage.ID)
		}
		if check.Message == "" {
			return fmt.Errorf("workflow: stage %q checks require message", stage.ID)
		}
		if check.CommandMatches != "" {
			re, err := compileWorkflowRegex(check.CommandMatches, check.CommandMatches)
			if err != nil {
				return fmt.Errorf("workflow: stage %q invalid command_matches regex %q: %w", stage.ID, check.CommandMatches, err)
			}
			check.commandMatchesRE = re
		}
		if check.CommandNotMatches != "" {
			re, err := compileWorkflowRegex(check.CommandNotMatches, check.CommandNotMatches)
			if err != nil {
				return fmt.Errorf("workflow: stage %q invalid command_not_matches regex %q: %w", stage.ID, check.CommandNotMatches, err)
			}
			check.commandNotRE = re
		}
	}
	if stage.Approval != nil && stage.Approval.Message == "" {
		return fmt.Errorf("workflow: stage %q approval.message is required", stage.ID)
	}
	return nil
}

// StageIndex returns the index for a stage ID.
func (d Definition) StageIndex(stageID string) (int, bool) {
	idx, ok := d.index[stageID]
	return idx, ok
}

// StageByID returns the stage with the given ID.
func (d Definition) StageByID(stageID string) (Stage, bool) {
	idx, ok := d.StageIndex(stageID)
	if !ok {
		return Stage{}, false
	}
	return d.Stages[idx], true
}
