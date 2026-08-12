package main

import (
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func TestParseThreshold(t *testing.T) {
	for value, want := range map[string]int{"never": 0, "info": 1, "warning": 2, "critical": 3} {
		got, err := parseThreshold(value)
		if err != nil || got != want {
			t.Fatalf("parseThreshold(%q) = %d, %v", value, got, err)
		}
	}
	if _, err := parseThreshold("nope"); err == nil {
		t.Fatal("invalid threshold should fail")
	}
}

func TestHasChanges(t *testing.T) {
	if hasChanges(infrascout.DiffReport{}) {
		t.Fatal("empty report has changes")
	}
	if !hasChanges(infrascout.DiffReport{Added: []infrascout.DiffItem{{ID: "x"}}}) {
		t.Fatal("added resource should count as a change")
	}
}
