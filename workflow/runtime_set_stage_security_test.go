package workflow

import (
	"context"
	"testing"
)

func TestSecurity_SetStageCannotBypassTargetStageApproval(t *testing.T) {
	rt := mustRuntime(t, stageMoveWorkflowYAML)
	sess := newWorkflowSession(t, "wf-set-stage-security")
	ctx := context.Background()

	if _, err := rt.SetStage(ctx, sess, "review"); err != nil {
		t.Fatalf("SetStage(review): %v", err)
	}

	push := makeCall(t, "Bash", map[string]any{"command": "git push origin feature-branch"})
	decision, err := rt.Evaluate(ctx, sess, push)
	if err != nil {
		t.Fatalf("Evaluate(push): %v", err)
	}
	if decision.Action != ActionPendingApproval || decision.StageID != "review" {
		t.Fatalf("unexpected decision after SetStage(review): %+v", decision)
	}
}
