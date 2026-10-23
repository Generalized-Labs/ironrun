package main

import (
	"errors"
	"testing"

	"github.com/generalized-labs/ironrun/internal/runner"
)

func TestValidateRunRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *runner.Result
		err    error
	}{
		{"execution error", nil, errors.New("probe failed")},
		{"missing result", nil, nil},
		{"failed child with complete output", &runner.Result{ExitCode: 1, Stdout: "starting job\npayload\ndone\n"}, nil},
		{"empty output", &runner.Result{}, nil},
		{"missing start", &runner.Result{Stdout: "payload\ndone\n"}, nil},
		{"missing end", &runner.Result{Stdout: "starting job\npayload"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRun(tc.result, tc.err, true); err == nil {
				t.Fatal("invalid probe accepted as evidence")
			}
		})
	}
	if err := validateRun(&runner.Result{Stdout: "starting job\n[REDACTED]\ndone\n"}, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePerformanceRun(t *testing.T) {
	if err := validateRun(&runner.Result{ExitCode: 1}, nil, false); err == nil {
		t.Fatal("failed child accepted as a performance sample")
	}
	if err := validateRun(&runner.Result{}, nil, false); err != nil {
		t.Fatalf("successful silent probe rejected: %v", err)
	}
}

func TestValidateExperiment(t *testing.T) {
	for _, name := range []string{"", "leak", "fp", "perf"} {
		if err := validateExperiment(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateExperiment("leaks"); err == nil {
		t.Fatal("unknown experiment silently accepted")
	}
}
