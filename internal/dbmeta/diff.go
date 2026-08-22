package dbmeta

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

type Diff struct {
	Version     string       `json:"version"`
	ComparedAt  string       `json:"compared_at"`
	Engine      string       `json:"engine"`
	HighestRisk string       `json:"highest_risk"`
	Added       []DiffItem   `json:"added"`
	Removed     []DiffItem   `json:"removed"`
	Changed     []DiffChange `json:"changed"`
	Unchanged   int          `json:"unchanged_count"`
}

// MergeIntoInfraReport folds database metadata drift into the same review and
// release-gate document as host/resource drift.
func MergeIntoInfraReport(report *infrascout.DiffReport, database Diff) {
	if report == nil {
		return
	}
	keepAdded := report.Added[:0]
	for _, item := range report.Added {
		if !strings.HasPrefix(item.Type, "database.") {
			keepAdded = append(keepAdded, item)
		}
	}
	report.Added = keepAdded
	keepRemoved := report.Removed[:0]
	for _, item := range report.Removed {
		if !strings.HasPrefix(item.Type, "database.") {
			keepRemoved = append(keepRemoved, item)
		}
	}
	report.Removed = keepRemoved
	keepChanged := report.Changed[:0]
	for _, item := range report.Changed {
		if !strings.HasPrefix(item.Type, "database.") {
			keepChanged = append(keepChanged, item)
		}
	}
	report.Changed = keepChanged
	for _, item := range database.Added {
		report.Added = append(report.Added, infrascout.DiffItem{ID: "dbmeta:" + item.ID, Type: "database." + item.Kind, Summary: "database " + item.Kind + " added: " + item.ID, Severity: infraSeverity(item.Severity), After: valueMap(item.Value)})
	}
	for _, item := range database.Removed {
		report.Removed = append(report.Removed, infrascout.DiffItem{ID: "dbmeta:" + item.ID, Type: "database." + item.Kind, Summary: "database " + item.Kind + " removed: " + item.ID, Severity: infraSeverity(item.Severity), Before: valueMap(item.Value)})
	}
	for _, item := range database.Changed {
		report.Changed = append(report.Changed, infrascout.ChangeItem{ID: "dbmeta:" + item.ID, Type: "database." + item.Kind, Summary: "database " + item.Kind + " changed: " + item.ID, Severity: infraSeverity(item.Severity), Before: valueMap(item.Before), After: valueMap(item.After)})
	}
	infrascout.RecalculateReport(report)
}

func infraSeverity(value string) infrascout.Severity {
	switch value {
	case "CRITICAL":
		return infrascout.SeverityCritical
	case "WARNING":
		return infrascout.SeverityWarning
	default:
		return infrascout.SeverityInfo
	}
}

func valueMap(value any) map[string]any {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	data, _ := json.Marshal(value)
	result := map[string]any{}
	_ = json.Unmarshal(data, &result)
	return result
}

type DiffItem struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Value    any    `json:"value"`
}

type DiffChange struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Before   any    `json:"before"`
	After    any    `json:"after"`
}

type flatObject struct {
	kind, id string
	value    any
}

func Compare(before, after Metadata) Diff {
	result := Diff{Version: "infrascout.database-diff/v2", ComparedAt: time.Now().UTC().Format(time.RFC3339), Engine: after.Engine, HighestRisk: "INFO", Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffChange{}}
	oldItems, newItems := flatten(before), flatten(after)
	for id, oldItem := range oldItems {
		newItem, ok := newItems[id]
		if !ok {
			severity := databaseSeverity(oldItem.kind, "removed")
			result.Removed = append(result.Removed, DiffItem{Kind: oldItem.kind, ID: id, Severity: severity, Value: oldItem.value})
			result.HighestRisk = higherRisk(result.HighestRisk, severity)
			continue
		}
		oldJSON, _ := json.Marshal(oldItem.value)
		newJSON, _ := json.Marshal(newItem.value)
		if string(oldJSON) == string(newJSON) {
			result.Unchanged++
		} else {
			severity := databaseSeverity(oldItem.kind, "changed")
			result.Changed = append(result.Changed, DiffChange{Kind: oldItem.kind, ID: id, Severity: severity, Before: oldItem.value, After: newItem.value})
			result.HighestRisk = higherRisk(result.HighestRisk, severity)
		}
	}
	for id, item := range newItems {
		if _, ok := oldItems[id]; ok {
			continue
		}
		severity := databaseSeverity(item.kind, "added")
		result.Added = append(result.Added, DiffItem{Kind: item.kind, ID: id, Severity: severity, Value: item.value})
		result.HighestRisk = higherRisk(result.HighestRisk, severity)
	}
	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].ID < result.Changed[j].ID })
	return result
}

func flatten(metadata Metadata) map[string]flatObject {
	out := map[string]flatObject{}
	for _, schema := range metadata.Schemas {
		for _, table := range schema.Tables {
			tableKey := tableID(schema.Name, table.Name)
			out[tableKey] = flatObject{kind: "table", id: tableKey, value: map[string]string{"schema": schema.Name, "name": table.Name}}
			for _, column := range table.Columns {
				id := columnID(schema.Name, table.Name, column.Name)
				out[id] = flatObject{kind: "column", id: id, value: column}
			}
		}
	}
	groups := []struct {
		kind   string
		values []Object
	}{{"index", metadata.Indexes}, {"view", metadata.Views}, {"trigger", metadata.Triggers}, {"routine", metadata.Routines}, {"privilege", metadata.Privileges}, {"role", metadata.Roles}}
	for _, group := range groups {
		for _, value := range group.values {
			id := objectID(group.kind, value)
			out[id] = flatObject{kind: group.kind, id: id, value: value}
		}
	}
	for _, value := range metadata.Constraints {
		id := constraintID(value)
		out[id] = flatObject{kind: "constraint", id: id, value: value}
	}
	return out
}

func databaseSeverity(kind, action string) string {
	if kind == "privilege" || kind == "role" {
		return "CRITICAL"
	}
	if action == "removed" && (kind == "table" || kind == "column") {
		return "CRITICAL"
	}
	if kind == "table" || kind == "column" || kind == "index" || kind == "trigger" || kind == "constraint" {
		return "WARNING"
	}
	return "INFO"
}

func higherRisk(left, right string) string {
	rank := map[string]int{"INFO": 1, "WARNING": 2, "CRITICAL": 3}
	if rank[right] > rank[left] {
		return right
	}
	return left
}
