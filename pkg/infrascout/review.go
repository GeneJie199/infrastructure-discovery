package infrascout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const DecisionSetVersion = "infrascout.decisions/v1"

type DriftClassification string

const (
	ClassificationExpected   DriftClassification = "expected"
	ClassificationApproved   DriftClassification = "approved"
	ClassificationTemporary  DriftClassification = "temporary"
	ClassificationUnexpected DriftClassification = "unexpected"
	ClassificationDenied     DriftClassification = "denied"
)

type DriftDecision struct {
	Fingerprint    string              `json:"fingerprint"`
	ResourceID     string              `json:"resource_id"`
	ChangeKind     string              `json:"change_kind"`
	Classification DriftClassification `json:"classification"`
	Actor          string              `json:"actor"`
	Note           string              `json:"note"`
	DecidedAt      string              `json:"decided_at"`
	ExpiresAt      string              `json:"expires_at,omitempty"`
}

type DecisionSet struct {
	Version   string          `json:"version"`
	UpdatedAt string          `json:"updated_at"`
	Decisions []DriftDecision `json:"decisions"`
}

func (set *DecisionSet) Normalize(now time.Time) error {
	if set.Version == "" {
		set.Version = DecisionSetVersion
	}
	if set.Version != DecisionSetVersion {
		return fmt.Errorf("unsupported decision set version %q", set.Version)
	}
	seen := map[string]bool{}
	for _, decision := range set.Decisions {
		if err := ValidateDecision(decision, now, false); err != nil {
			return err
		}
		if seen[decision.Fingerprint] {
			return fmt.Errorf("duplicate decision fingerprint %s", decision.Fingerprint)
		}
		seen[decision.Fingerprint] = true
	}
	return nil
}

func ValidateDecision(decision DriftDecision, now time.Time, requireFutureExpiry bool) error {
	if !strings.HasPrefix(decision.Fingerprint, "drift_") || decision.ResourceID == "" || decision.ChangeKind == "" {
		return errors.New("decision requires a drift fingerprint, resource_id, and change_kind")
	}
	if strings.TrimSpace(decision.Actor) == "" || strings.TrimSpace(decision.Note) == "" {
		return errors.New("decision requires actor and note")
	}
	switch decision.Classification {
	case ClassificationExpected, ClassificationApproved, ClassificationUnexpected, ClassificationDenied:
		if decision.ExpiresAt != "" {
			return errors.New("expires_at is only valid for temporary decisions")
		}
	case ClassificationTemporary:
		expires, err := time.Parse(time.RFC3339, decision.ExpiresAt)
		if err != nil {
			return errors.New("temporary decision requires RFC3339 expires_at")
		}
		if requireFutureExpiry && !expires.After(now) {
			return errors.New("temporary decision expiry must be in the future")
		}
	default:
		return fmt.Errorf("invalid classification %q", decision.Classification)
	}
	if _, err := time.Parse(time.RFC3339, decision.DecidedAt); err != nil {
		return errors.New("decision requires RFC3339 decided_at")
	}
	return nil
}

func (set *DecisionSet) Upsert(decision DriftDecision, now time.Time) error {
	if err := ValidateDecision(decision, now, true); err != nil {
		return err
	}
	set.Version = DecisionSetVersion
	set.UpdatedAt = FormatTime(now)
	for index := range set.Decisions {
		if set.Decisions[index].Fingerprint == decision.Fingerprint {
			set.Decisions[index] = decision
			return nil
		}
	}
	set.Decisions = append(set.Decisions, decision)
	sort.Slice(set.Decisions, func(i, j int) bool { return set.Decisions[i].Fingerprint < set.Decisions[j].Fingerprint })
	return nil
}

func ApplyDecisions(report *DiffReport, set DecisionSet, now time.Time) {
	byFingerprint := map[string]DriftDecision{}
	for _, decision := range set.Decisions {
		byFingerprint[decision.Fingerprint] = decision
	}
	report.ClassificationCounts = map[DriftClassification]int{}
	blocking := []Severity{}
	apply := func(kind string, id, resourceType, summary string, before, after map[string]any, severity Severity) (string, DriftClassification, *DriftDecision, bool) {
		fingerprint := DriftFingerprint(kind, id, resourceType, summary, before, after)
		classification := ClassificationUnexpected
		var applied *DriftDecision
		expired := false
		if decision, ok := byFingerprint[fingerprint]; ok {
			classification = decision.Classification
			if classification == ClassificationTemporary {
				expires, err := time.Parse(time.RFC3339, decision.ExpiresAt)
				if err != nil || !expires.After(now) {
					classification = ClassificationUnexpected
					expired = true
				}
			}
			copy := decision
			applied = &copy
		}
		report.ClassificationCounts[classification]++
		if classification == ClassificationUnexpected || classification == ClassificationDenied {
			blocking = append(blocking, severity)
		}
		return fingerprint, classification, applied, expired
	}
	for index := range report.Added {
		item := &report.Added[index]
		item.Fingerprint, item.Classification, item.Decision, item.DecisionExpired = apply("added", item.ID, item.Type, item.Summary, item.Before, item.After, item.Severity)
	}
	for index := range report.Removed {
		item := &report.Removed[index]
		item.Fingerprint, item.Classification, item.Decision, item.DecisionExpired = apply("removed", item.ID, item.Type, item.Summary, item.Before, item.After, item.Severity)
	}
	for index := range report.Changed {
		item := &report.Changed[index]
		item.Fingerprint, item.Classification, item.Decision, item.DecisionExpired = apply("changed", item.ID, item.Type, item.Summary, item.Before, item.After, item.Severity)
	}
	if len(blocking) == 0 {
		report.BlockingRisk = ""
	} else {
		report.BlockingRisk = highest(blocking)
	}
}

func DriftFingerprint(kind, id, resourceType, summary string, before, after map[string]any) string {
	payload := struct {
		Kind, ID, Type, Summary string
		Before, After           map[string]any
	}{kind, id, resourceType, summary, before, after}
	encoded, _ := json.Marshal(payload)
	hash := sha256.Sum256(encoded)
	return "drift_" + hex.EncodeToString(hash[:12])
}

func FindDriftItem(report DiffReport, fingerprint, resourceID string) (string, string, string, error) {
	matches := [][3]string{}
	add := func(kind, id, currentFingerprint string) {
		if fingerprint != "" && currentFingerprint != fingerprint {
			return
		}
		if resourceID != "" && id != resourceID {
			return
		}
		matches = append(matches, [3]string{currentFingerprint, id, kind})
	}
	for _, item := range report.Added {
		add("added", item.ID, item.Fingerprint)
	}
	for _, item := range report.Removed {
		add("removed", item.ID, item.Fingerprint)
	}
	for _, item := range report.Changed {
		add("changed", item.ID, item.Fingerprint)
	}
	if len(matches) != 1 {
		return "", "", "", fmt.Errorf("change selector matched %d items", len(matches))
	}
	return matches[0][0], matches[0][1], matches[0][2], nil
}

// PromoteResource applies one reviewed resource change to a baseline without
// accepting unrelated resources from the current snapshot.
func PromoteResource(baseline *Snapshot, current Snapshot, resourceID, kind string) {
	resources := make([]Resource, 0, len(baseline.Resources)+1)
	for _, resource := range baseline.Resources {
		if resource.ID != resourceID {
			resources = append(resources, resource)
		}
	}
	if kind != "removed" {
		for _, resource := range current.Resources {
			if resource.ID == resourceID {
				resources = append(resources, resource)
				break
			}
		}
	}
	baseline.Resources = resources
	relationships := make([]Relationship, 0, len(baseline.Relationships))
	for _, relationship := range baseline.Relationships {
		if relationship.Source != resourceID && relationship.Target != resourceID {
			relationships = append(relationships, relationship)
		}
	}
	if kind != "removed" {
		for _, relationship := range current.Relationships {
			if relationship.Source == resourceID || relationship.Target == resourceID {
				relationships = append(relationships, relationship)
			}
		}
	}
	baseline.Relationships = relationships
}
