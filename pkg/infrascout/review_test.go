package infrascout

import (
	"testing"
	"time"
)

func TestApplyDecisionsSeparatesObservedRiskFromBlockingRisk(t *testing.T) {
	now := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	report := DiffReport{Added: []DiffItem{{ID: "endpoint:public", Type: "endpoint", Summary: "new public listener", Severity: SeverityCritical}}}
	ApplyDecisions(&report, DecisionSet{}, now)
	if report.Added[0].Classification != ClassificationUnexpected || report.BlockingRisk != SeverityCritical || report.HighestRisk != "" {
		t.Fatalf("default disposition = %+v", report)
	}

	fingerprint := report.Added[0].Fingerprint
	approved := DriftDecision{Fingerprint: fingerprint, ResourceID: "endpoint:public", ChangeKind: "added", Classification: ClassificationApproved, Actor: "owner", Note: "release rel-7", DecidedAt: FormatTime(now)}
	ApplyDecisions(&report, DecisionSet{Version: DecisionSetVersion, Decisions: []DriftDecision{approved}}, now)
	if report.Added[0].Classification != ClassificationApproved || report.BlockingRisk != "" || report.ClassificationCounts[ClassificationApproved] != 1 {
		t.Fatalf("approved disposition = %+v", report)
	}
}

func TestTemporaryDecisionExpiresBackToUnexpected(t *testing.T) {
	now := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	report := DiffReport{Changed: []ChangeItem{{ID: "service:web", Type: "service", Summary: "service changed", Severity: SeverityWarning, Before: map[string]any{"image": "v1"}, After: map[string]any{"image": "v2"}}}}
	ApplyDecisions(&report, DecisionSet{}, now)
	decision := DriftDecision{Fingerprint: report.Changed[0].Fingerprint, ResourceID: "service:web", ChangeKind: "changed", Classification: ClassificationTemporary, Actor: "oncall", Note: "incident mitigation", DecidedAt: FormatTime(now.Add(-time.Hour)), ExpiresAt: FormatTime(now.Add(-time.Minute))}
	ApplyDecisions(&report, DecisionSet{Version: DecisionSetVersion, Decisions: []DriftDecision{decision}}, now)
	if !report.Changed[0].DecisionExpired || report.Changed[0].Classification != ClassificationUnexpected || report.BlockingRisk != SeverityWarning {
		t.Fatalf("expired disposition = %+v", report.Changed[0])
	}
	decision.ExpiresAt = FormatTime(now.Add(time.Hour))
	ApplyDecisions(&report, DecisionSet{Version: DecisionSetVersion, Decisions: []DriftDecision{decision}}, now)
	if report.Changed[0].DecisionExpired || report.Changed[0].Classification != ClassificationTemporary || report.BlockingRisk != "" {
		t.Fatalf("active temporary disposition = %+v", report.Changed[0])
	}
}

func TestDecisionUpsertRequiresAuditFieldsAndFutureTemporaryExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	set := DecisionSet{}
	base := DriftDecision{Fingerprint: "drift_123456", ResourceID: "service:web", ChangeKind: "changed", Classification: ClassificationApproved, DecidedAt: FormatTime(now)}
	if err := set.Upsert(base, now); err == nil {
		t.Fatal("decision without actor and note should fail")
	}
	base.Actor, base.Note = "owner", "reviewed"
	if err := set.Upsert(base, now); err != nil || len(set.Decisions) != 1 {
		t.Fatalf("approved upsert = %+v, %v", set, err)
	}
	base.Classification = ClassificationTemporary
	base.ExpiresAt = FormatTime(now.Add(-time.Minute))
	if err := set.Upsert(base, now); err == nil {
		t.Fatal("past temporary expiry should fail")
	}
}

func TestDriftFingerprintChangesWithChangedValues(t *testing.T) {
	one := DriftFingerprint("changed", "service:web", "service", "changed", map[string]any{"image": "v1"}, map[string]any{"image": "v2"})
	two := DriftFingerprint("changed", "service:web", "service", "changed", map[string]any{"image": "v1"}, map[string]any{"image": "v3"})
	if one == two {
		t.Fatal("materially different changes shared a fingerprint")
	}
}
