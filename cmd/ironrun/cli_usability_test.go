package main

import (
	"testing"

	"github.com/generalized-labs/ironrun/internal/envset"
)

func TestEverydayCommandAliases(t *testing.T) {
	tests := []struct {
		name    string
		aliases []string
		want    string
	}{
		{runCmd().Name(), runCmd().Aliases, "run"},
		{envCmd().Name(), envCmd().Aliases, "vault"},
		{accessCmd().Name(), accessCmd().Aliases, "access"},
		{capsuleCmd().Name(), capsuleCmd().Aliases, "capsule"},
		{serveCmd().Name(), serveCmd().Aliases, "serve"},
		{tuiCmd().Name(), tuiCmd().Aliases, "tui"},
		{initCmd().Name(), initCmd().Aliases, "init"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, alias := range tt.aliases {
				if alias == tt.want {
					return
				}
			}
			t.Fatalf("aliases %v do not contain %q", tt.aliases, tt.want)
		})
	}
}

func TestEnvironmentSetTargetDefaultsToActive(t *testing.T) {
	m := &envset.Manager{Meta: envset.Metadata{Active: "staging"}}
	name, key, err := environmentSetTarget(m, []string{"OPENAI_API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "staging" || key != "OPENAI_API_KEY" {
		t.Fatalf("got %q %q", name, key)
	}
}

func TestEnvironmentSetTargetKeepsExplicitEnvironment(t *testing.T) {
	m := &envset.Manager{}
	name, key, err := environmentSetTarget(m, []string{"prod", "DATABASE_URL"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "prod" || key != "DATABASE_URL" {
		t.Fatalf("got %q %q", name, key)
	}
}
