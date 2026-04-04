package adapter

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	edictum "github.com/edictum-ai/edictum-go"
	"github.com/edictum-ai/edictum-go/audit"
	"github.com/edictum-ai/edictum-go/workflow"
)

func assertStepOutcome(t *testing.T, fixtureID string, step workflowAdapterStep, err error) {
	t.Helper()

	switch {
	case step.Expect.Decision == "block":
		var blocked *edictum.BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("%s/%s error = %T, want *BlockedError", fixtureID, step.ID, err)
		}
	case step.Execution == "error":
		var toolErr *edictum.ToolError
		if !errors.As(err, &toolErr) {
			t.Fatalf("%s/%s error = %T, want *ToolError", fixtureID, step.ID, err)
		}
	default:
		if err != nil {
			t.Fatalf("%s/%s unexpected error: %v", fixtureID, step.ID, err)
		}
	}
}

func assertWorkflowState(t *testing.T, fixtureID, stepID string, got workflow.State, expect workflowAdapterExpect) {
	t.Helper()

	if got.ActiveStage != expect.ActiveStage {
		t.Fatalf("%s/%s active_stage = %q, want %q", fixtureID, stepID, got.ActiveStage, expect.ActiveStage)
	}
	if !reflect.DeepEqual(got.CompletedStages, expect.CompletedStages) {
		t.Fatalf("%s/%s completed_stages = %+v, want %+v", fixtureID, stepID, got.CompletedStages, expect.CompletedStages)
	}
	if !reflect.DeepEqual(normalizeStringMap(got.Approvals), normalizeStringMap(expect.Approvals)) {
		t.Fatalf("%s/%s approvals = %+v, want %+v", fixtureID, stepID, got.Approvals, expect.Approvals)
	}
	if !reflect.DeepEqual(got.Evidence.Reads, expect.Evidence.Reads) {
		t.Fatalf("%s/%s reads = %+v, want %+v", fixtureID, stepID, got.Evidence.Reads, expect.Evidence.Reads)
	}
	if !reflect.DeepEqual(normalizeStageCalls(got.Evidence.StageCalls), normalizeStageCalls(expect.Evidence.StageCalls)) {
		t.Fatalf("%s/%s stage_calls = %+v, want %+v", fixtureID, stepID, got.Evidence.StageCalls, expect.Evidence.StageCalls)
	}

	wantBlocked := ""
	if expect.BlockedReason != nil {
		wantBlocked = *expect.BlockedReason
	}
	if got.BlockedReason != wantBlocked {
		t.Fatalf("%s/%s blocked_reason = %q, want %q", fixtureID, stepID, got.BlockedReason, wantBlocked)
	}
	if got.PendingApproval != expect.PendingApproval {
		t.Fatalf("%s/%s pending_approval = %+v, want %+v", fixtureID, stepID, got.PendingApproval, expect.PendingApproval)
	}
}

func normalizeStringMap(value map[string]string) map[string]string {
	if value == nil {
		return map[string]string{}
	}
	return value
}

func normalizeStageCalls(value map[string][]string) map[string][]string {
	if value == nil {
		return map[string][]string{}
	}
	return value
}

func assertAuditEvents(t *testing.T, fixtureID, stepID string, got []audit.Event, expect []map[string]any) {
	t.Helper()

	if len(got) != len(expect) {
		t.Fatalf("%s/%s audit event count = %d, want %d", fixtureID, stepID, len(got), len(expect))
	}
	for idx := range expect {
		expectEvent := expect[idx]
		if wantAction, _ := expectEvent["action"].(string); string(got[idx].Action) != wantAction {
			t.Fatalf("%s/%s event[%d] action = %q, want %q", fixtureID, stepID, idx, got[idx].Action, wantAction)
		}
		if wantSession, ok := expectEvent["session_id"].(string); ok && got[idx].SessionID != wantSession {
			t.Fatalf("%s/%s event[%d] session_id = %q, want %q", fixtureID, stepID, idx, got[idx].SessionID, wantSession)
		}
		if wantParent, ok := expectEvent["parent_session_id"].(string); ok && got[idx].ParentSessionID != wantParent {
			t.Fatalf("%s/%s event[%d] parent_session_id = %q, want %q", fixtureID, stepID, idx, got[idx].ParentSessionID, wantParent)
		}
		if wantWorkflow, ok := expectEvent["workflow"].(map[string]any); ok {
			assertSubsetValue(t, fmt.Sprintf("%s/%s event[%d].workflow", fixtureID, stepID, idx), got[idx].Workflow, wantWorkflow)
		}
	}
}

func assertSubsetValue(t *testing.T, label string, actual, expected any) {
	t.Helper()

	switch want := expected.(type) {
	case nil:
		if actual != nil {
			t.Fatalf("%s = %#v, want nil", label, actual)
		}
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok {
			t.Fatalf("%s type = %T, want map[string]any", label, actual)
		}
		for key, value := range want {
			gotValue, ok := got[key]
			if !ok {
				t.Fatalf("%s missing key %q", label, key)
			}
			assertSubsetValue(t, label+"."+key, gotValue, value)
		}
	case []any:
		got, ok := actual.([]any)
		if !ok {
			t.Fatalf("%s type = %T, want []any", label, actual)
		}
		if len(got) != len(want) {
			t.Fatalf("%s len = %d, want %d", label, len(got), len(want))
		}
		for idx := range want {
			assertSubsetValue(t, fmt.Sprintf("%s[%d]", label, idx), got[idx], want[idx])
		}
	default:
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s = %#v, want %#v", label, actual, expected)
		}
	}
}
