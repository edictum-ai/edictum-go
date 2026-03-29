package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

type gateSubprocessCapture struct {
	stderr string
}

func gateSubprocessCallable(runnerArgs []string, raw []byte) (func(map[string]any) (any, error), *gateSubprocessCapture) {
	capture := &gateSubprocessCapture{}
	return func(_ map[string]any) (any, error) {
		proc := exec.Command(runnerArgs[0], runnerArgs[1:]...) //nolint:gosec // Child command is the explicit CLI API.
		proc.Stdin = bytes.NewReader(raw)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		proc.Stdout = &stdout
		proc.Stderr = &stderr

		err := proc.Run()
		capture.stderr = stderr.String()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = strings.TrimSpace(stdout.String())
			}
			if msg == "" {
				msg = err.Error()
			}
			return nil, errors.New(msg)
		}

		return stdout.String(), nil
	}, capture
}
