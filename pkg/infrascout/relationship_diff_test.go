package infrascout

import (
	"strings"
	"testing"
	"time"
)

func TestRelationshipDriftCanBeReviewedAndPromoted(t *testing.T) {
	relationship := Relationship{Source: "nginx.route:a", Target: "endpoint:a", Type: "proxies_to", Confidence: .95, Evidence: []string{"nginx.conf"}}
	baseline := Snapshot{State: "approved"}
	current := Snapshot{State: "observed", Relationships: []Relationship{relationship}}
	report := Compare(baseline, current)
	if len(report.Added) != 1 || report.Added[0].Type != "relationship" || !strings.HasPrefix(report.Added[0].ID, "relationship:") {
		t.Fatalf("relationship drift=%+v", report.Added)
	}
	ApplyDecisions(&report, DecisionSet{}, time.Now())
	if report.Added[0].Fingerprint == "" || report.Added[0].Classification != ClassificationUnexpected {
		t.Fatalf("relationship review metadata=%+v", report.Added[0])
	}
	PromoteResource(&baseline, current, report.Added[0].ID, "added")
	if len(baseline.Relationships) != 1 || RelationshipID(baseline.Relationships[0]) != report.Added[0].ID {
		t.Fatalf("promoted relationships=%+v", baseline.Relationships)
	}
}

func TestRelationshipEvidenceDoesNotCreateDrift(t *testing.T) {
	baseline := Snapshot{Relationships: []Relationship{{
		Source: "process:api", Target: "endpoint:8080", Type: "listens_on", Confidence: .9,
		Evidence: []string{"socket inode mapped to pid 120"},
	}}}
	current := Snapshot{Relationships: []Relationship{{
		Source: "process:api", Target: "endpoint:8080", Type: "listens_on", Confidence: .9,
		Evidence: []string{"socket inode mapped to pid 981"},
	}}}
	report := Compare(baseline, current)
	if len(report.Added)+len(report.Removed)+len(report.Changed) != 0 {
		t.Fatalf("volatile relationship evidence created drift: %+v", report)
	}
}
