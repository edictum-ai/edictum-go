package workflow

const stageMoveWorkflowYAML = `apiVersion: edictum/v1
kind: Workflow
metadata:
  name: stage-move-process
stages:
  - id: discover
    tools: [Read]
    exit:
      - condition: file_read("specs/008.md")
        message: Read the workflow spec first
  - id: implement
    entry:
      - condition: stage_complete("discover")
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Approval required before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
`

func stageMoveSeedState() State {
	return State{
		ActiveStage:     "push",
		CompletedStages: []string{"discover", "implement", "review"},
		Approvals: map[string]string{
			"review": approvedStatus,
		},
		Evidence: Evidence{
			Reads: []string{"specs/008.md"},
			StageCalls: map[string][]string{
				"push": {"git push origin feature-branch"},
			},
		},
		BlockedReason: "Approval required before push",
		PendingApproval: PendingApproval{
			Required: true,
			StageID:  "review",
			Message:  "Approval required before push",
		},
		LastRecordedEvidence: &EvidenceRecord{
			Tool:      "Bash",
			Summary:   "git",
			Timestamp: "2026-04-04T10:00:00Z",
		},
		LastBlockedAction: &BlockedAction{
			Tool:      "Bash",
			Summary:   "git",
			Message:   "Approval required before push",
			Timestamp: "2026-04-04T10:05:00Z",
		},
	}
}
