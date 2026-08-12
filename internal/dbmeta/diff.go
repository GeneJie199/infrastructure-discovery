package dbmeta

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
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
	result := Diff{Version: "infrascout.database-diff/v1", ComparedAt: time.Now().UTC().Format(time.RFC3339), Engine: after.Engine, HighestRisk: "INFO", Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffChange{}}
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
			tableID := fmt.Sprintf("table:%s.%s", schema.Name, table.Name)
			out[tableID] = flatObject{kind: "table", id: tableID, value: map[string]string{"schema": schema.Name, "name": table.Name}}
			for _, column := range table.Columns {
				id := fmt.Sprintf("column:%s.%s.%s", schema.Name, table.Name, column.Name)
				out[id] = flatObject{kind: "column", id: id, value: column}
			}
		}
	}
	groups := []struct {
		kind   string
		values []Object
	}{{"index", metadata.Indexes}, {"view", metadata.Views}, {"trigger", metadata.Triggers}, {"routine", metadata.Routines}, {"privilege", metadata.Privileges}}
	for _, group := range groups {
		for _, value := range group.values {
			id := fmt.Sprintf("%s:%s.%s.%s", group.kind, value.Schema, value.Name, value.Type)
			out[id] = flatObject{kind: group.kind, id: id, value: value}
		}
	}
	return out
}

func databaseSeverity(kind, action string) string {
	if kind == "privilege" {
		return "CRITICAL"
	}
	if action == "removed" && (kind == "table" || kind == "column") {
		return "CRITICAL"
	}
	if kind == "table" || kind == "column" || kind == "index" || kind == "trigger" {
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
