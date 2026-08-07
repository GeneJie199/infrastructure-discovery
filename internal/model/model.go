// Package model defines Inventory and Snapshot shapes aligned with lifecycle-spec v0.1.
package model

import "time"

const SpecVersion = "0.1.0"

// DefaultNoiseFilteredFields lists attribute paths excluded from snapshot diff.
// PID and process start time are collected as attributes but treated as noise.
var DefaultNoiseFilteredFields = []string{
	"attributes.pid",
	"attributes.startedAt",
}

// Source identifies the producing product instance (lifecycle-spec defs.source).
type Source struct {
	Product    string `json:"product"`
	InstanceID string `json:"instanceId"`
	Version    string `json:"version,omitempty"`
}

// Context is optional scan context (lifecycle-spec defs.context).
type Context struct {
	ProjectID       string            `json:"projectId,omitempty"`
	Environment     string            `json:"environment,omitempty"`
	ResourceGroupID string            `json:"resourceGroupId,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// Digest is an optional integrity hash (lifecycle-spec defs.digest).
type Digest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// NoisePolicy declares fields ignored by snapshot comparison.
type NoisePolicy struct {
	FilteredFields []string `json:"filteredFields,omitempty"`
	Notes          string   `json:"notes,omitempty"`
}

// Resource is a managed entity with a stable resourceId (lifecycle-spec resource).
// Attributes must not contain plaintext secrets.
type Resource struct {
	SpecVersion      string         `json:"specVersion,omitempty"`
	ResourceID       string         `json:"resourceId"`
	ResourceType     string         `json:"resourceType"`
	DisplayName      string         `json:"displayName"`
	Attributes       map[string]any `json:"attributes,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	FirstSeenAt      string         `json:"firstSeenAt,omitempty"`
	LastSeenAt       string         `json:"lastSeenAt,omitempty"`
	ParentResourceID string         `json:"parentResourceId,omitempty"`
}

// Relationship links two resources (lifecycle-spec relationship).
type Relationship struct {
	SpecVersion    string         `json:"specVersion,omitempty"`
	RelationshipID string         `json:"relationshipId"`
	Type           string         `json:"type"`
	From           string         `json:"from"`
	To             string         `json:"to"`
	Attributes     map[string]any `json:"attributes,omitempty"`
	ObservedAt     string         `json:"observedAt,omitempty"`
}

// Inventory is a stable resource catalog derived from a scan (inventory.json).
// It omits volatile process attributes (pid, startedAt) while retaining identity.
type Inventory struct {
	SpecVersion  string     `json:"specVersion"`
	InventoryID  string     `json:"inventoryId"`
	CapturedAt   string     `json:"capturedAt"`
	Source       Source     `json:"source"`
	Context      *Context   `json:"context,omitempty"`
	HostResource string     `json:"hostResourceId"`
	Resources    []Resource `json:"resources"`
}

// Snapshot is a point-in-time state photo used for diffs (snapshot.json).
type Snapshot struct {
	SpecVersion   string         `json:"specVersion"`
	SnapshotID    string         `json:"snapshotId"`
	CapturedAt    string         `json:"capturedAt"`
	Source        Source         `json:"source"`
	Context       *Context       `json:"context,omitempty"`
	NoisePolicy   NoisePolicy    `json:"noisePolicy"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships,omitempty"`
	Digest        *Digest        `json:"digest,omitempty"`
}

// DriftReport is the JSON result of comparing two snapshots.
type DriftReport struct {
	SpecVersion   string       `json:"specVersion"`
	ComparedAt    string       `json:"comparedAt"`
	BaselineID    string       `json:"baselineSnapshotId"`
	CandidateID   string       `json:"candidateSnapshotId"`
	FilteredFields []string    `json:"filteredFields"`
	Added         []Resource   `json:"added"`
	Removed       []Resource   `json:"removed"`
	Changed       []Change     `json:"changed"`
	UnchangedCount int         `json:"unchangedCount"`
}

// Change describes attribute-level drift for one resourceId.
type Change struct {
	ResourceID string         `json:"resourceId"`
	Before     map[string]any `json:"before,omitempty"`
	After      map[string]any `json:"after,omitempty"`
}

// FormatTime returns an RFC3339 timestamp with timezone offset.
func FormatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}
