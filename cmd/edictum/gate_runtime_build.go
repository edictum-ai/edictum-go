package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/edictum-ai/edictum-go/approval"
	"github.com/edictum-ai/edictum-go/guard"
	"github.com/edictum-ai/edictum-go/server"
	"github.com/edictum-ai/edictum-go/session"
	"github.com/edictum-ai/edictum-go/workflow"
)

const gateApprovalPollInterval = 100 * time.Millisecond

type gateGuardConfig struct {
	RulesPath           string
	WorkflowPath        string
	WorkflowExecEnabled bool
	ServerURL           string
	APIKey              string
}

func buildGateGuard(cfg gateGuardConfig) (*guard.Guard, error) {
	statePath, err := gateSessionStorePath()
	if err != nil {
		return nil, err
	}
	backend := newGateFileBackend(statePath)

	approvalBackend, err := newGateApprovalBackend(cfg.ServerURL, cfg.APIKey)
	if err != nil {
		return nil, err
	}

	return buildGateGuardWithDeps(cfg, backend, approvalBackend)
}

func buildGateGuardWithDeps(cfg gateGuardConfig, backend session.StorageBackend, approvalBackend approval.Backend) (*guard.Guard, error) {
	if cfg.RulesPath == "" {
		return nil, fmt.Errorf("no rules configured")
	}

	opts := []guard.Option{guard.WithBackend(backend)}
	if approvalBackend != nil {
		opts = append(opts, guard.WithApprovalBackend(approvalBackend))
	}
	if cfg.WorkflowPath != "" {
		rt, err := loadGateWorkflowRuntime(cfg.WorkflowPath, cfg.WorkflowExecEnabled)
		if err != nil {
			return nil, err
		}
		opts = append(opts, guard.WithWorkflowRuntime(rt))
	}

	g, err := guard.FromYAML(cfg.RulesPath, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}
	return g, nil
}

func loadGateWorkflowRuntime(path string, execEnabled bool) (*workflow.Runtime, error) {
	def, err := workflow.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading workflow: %w", err)
	}
	var opts []workflow.RuntimeOption
	if execEnabled {
		opts = append(opts, workflow.WithExecEvaluatorEnabled())
	}
	rt, err := workflow.NewRuntime(def, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading workflow: %w", err)
	}
	return rt, nil
}

func newGateApprovalBackend(serverURL, apiKey string) (approval.Backend, error) {
	if serverURL == "" {
		return nil, nil
	}

	client, err := server.NewClient(server.ClientConfig{
		BaseURL: serverURL,
		APIKey:  apiKey,
		AgentID: "gate-cli",
		Env:     "production",
	})
	if err != nil {
		return nil, fmt.Errorf("configuring approval backend: %w", err)
	}
	return server.NewApprovalBackend(client, server.WithPollInterval(gateApprovalPollInterval)), nil
}

func gateSessionStorePath() (string, error) {
	gateDir, err := gateDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(gateDir, "state", "sessions.json"), nil
}
