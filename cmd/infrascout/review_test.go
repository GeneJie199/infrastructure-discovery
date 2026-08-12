package main

import (
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func TestPromoteResourceUpdatesOnlySelectedResourceAndRelationships(t *testing.T) {
	baseline := infrascout.Snapshot{
		Resources:     []infrascout.Resource{{ID: "service:a", Type: "service"}, {ID: "service:b", Type: "service"}},
		Relationships: []infrascout.Relationship{{Source: "host:a", Target: "service:a"}, {Source: "host:b", Target: "service:b"}},
	}
	current := infrascout.Snapshot{
		Resources:     []infrascout.Resource{{ID: "service:a", Type: "service", Metadata: map[string]any{"image": "v2"}}, {ID: "service:b", Type: "service", Metadata: map[string]any{"image": "unknown-change"}}},
		Relationships: []infrascout.Relationship{{Source: "host:new", Target: "service:a"}, {Source: "host:b", Target: "service:b"}},
	}
	infrascout.PromoteResource(&baseline, current, "service:a", "changed")
	if baseline.Resources[0].ID != "service:b" || baseline.Resources[0].Metadata != nil {
		t.Fatalf("unselected resource changed: %+v", baseline.Resources)
	}
	foundSelected := false
	for _, resource := range baseline.Resources {
		if resource.ID == "service:a" && resource.Metadata["image"] == "v2" {
			foundSelected = true
		}
	}
	if !foundSelected || len(baseline.Relationships) != 2 {
		t.Fatalf("selected resource not promoted: %+v %+v", baseline.Resources, baseline.Relationships)
	}
}

func TestPromoteRemovedResourceDeletesItsRelationships(t *testing.T) {
	baseline := infrascout.Snapshot{Resources: []infrascout.Resource{{ID: "service:a"}, {ID: "service:b"}}, Relationships: []infrascout.Relationship{{Source: "service:a", Target: "service:b"}}}
	infrascout.PromoteResource(&baseline, infrascout.Snapshot{}, "service:a", "removed")
	if len(baseline.Resources) != 1 || baseline.Resources[0].ID != "service:b" || len(baseline.Relationships) != 0 {
		t.Fatalf("removed promotion = %+v", baseline)
	}
}
