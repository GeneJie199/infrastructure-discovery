package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func TestInitializeStateCreatesImmediatelyServeableState(t *testing.T) {
	dir := t.TempDir()
	result := &infrascout.ScanResult{Inventory: infrascout.Inventory{Hostname: "node-a"}, Snapshot: infrascout.Snapshot{Hostname: "node-a"}}
	if err := initializeState(dir, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"baseline.json", "current.json", "inventory.json", "drift.json", "decisions.json", "monitoring-plan.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	baseline, err := readSnapshot(filepath.Join(dir, "baseline.json"))
	if err != nil || baseline.State != "approved" {
		t.Fatalf("baseline=%+v, %v", baseline, err)
	}
	current, err := readSnapshot(filepath.Join(dir, "current.json"))
	if err != nil || current.State != "observed" {
		t.Fatalf("current=%+v, %v", current, err)
	}
}
