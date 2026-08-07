// Package diff compares two snapshots while honoring noisePolicy.filteredFields.
package diff

import (
	"reflect"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/model"
)

// Compare produces a DriftReport between baseline and candidate snapshots.
// Filtered fields come from candidate.noisePolicy (fallback: baseline, then defaults).
func Compare(baseline, candidate model.Snapshot) model.DriftReport {
	filtered := candidate.NoisePolicy.FilteredFields
	if len(filtered) == 0 {
		filtered = baseline.NoisePolicy.FilteredFields
	}
	if len(filtered) == 0 {
		filtered = append([]string{}, model.DefaultNoiseFilteredFields...)
	}

	baseIdx := indexResources(baseline.Resources)
	candIdx := indexResources(candidate.Resources)

	report := model.DriftReport{
		SpecVersion:    model.SpecVersion,
		ComparedAt:     model.FormatTime(time.Now()),
		BaselineID:     baseline.SnapshotID,
		CandidateID:    candidate.SnapshotID,
		FilteredFields: filtered,
		Added:          []model.Resource{},
		Removed:        []model.Resource{},
		Changed:        []model.Change{},
	}

	unchanged := 0
	for id, cand := range candIdx {
		base, ok := baseIdx[id]
		if !ok {
			report.Added = append(report.Added, cand)
			continue
		}
		before, after, changed := attrDiff(base.Attributes, cand.Attributes, filtered)
		if changed {
			report.Changed = append(report.Changed, model.Change{
				ResourceID: id,
				Before:     before,
				After:      after,
			})
		} else {
			unchanged++
		}
	}
	for id, base := range baseIdx {
		if _, ok := candIdx[id]; !ok {
			report.Removed = append(report.Removed, base)
		}
	}
	report.UnchangedCount = unchanged
	return report
}

func indexResources(resources []model.Resource) map[string]model.Resource {
	out := make(map[string]model.Resource, len(resources))
	for _, r := range resources {
		out[r.ResourceID] = r
	}
	return out
}

func attrDiff(before, after map[string]any, filtered []string) (map[string]any, map[string]any, bool) {
	skip := filteredSet(filtered)
	bNorm := normalizeAttrs(before, skip)
	aNorm := normalizeAttrs(after, skip)

	changedBefore := map[string]any{}
	changedAfter := map[string]any{}
	keys := map[string]struct{}{}
	for k := range bNorm {
		keys[k] = struct{}{}
	}
	for k := range aNorm {
		keys[k] = struct{}{}
	}
	for k := range keys {
		bv, bok := bNorm[k]
		av, aok := aNorm[k]
		if !bok {
			changedAfter[k] = av
			continue
		}
		if !aok {
			changedBefore[k] = bv
			continue
		}
		if !reflect.DeepEqual(bv, av) {
			changedBefore[k] = bv
			changedAfter[k] = av
		}
	}
	if len(changedBefore) == 0 && len(changedAfter) == 0 {
		return nil, nil, false
	}
	return changedBefore, changedAfter, true
}

func filteredSet(filtered []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range filtered {
		f = strings.TrimSpace(f)
		f = strings.TrimPrefix(f, "attributes.")
		if f != "" {
			out[f] = struct{}{}
		}
	}
	return out
}

func normalizeAttrs(attrs map[string]any, skip map[string]struct{}) map[string]any {
	out := map[string]any{}
	for k, v := range attrs {
		if _, ok := skip[k]; ok {
			continue
		}
		out[k] = v
	}
	return out
}
