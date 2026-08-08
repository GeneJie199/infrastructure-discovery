// Package infrascout is the reusable InfraScout discovery library.
// FleetScope Agent can import this package without depending on CLI code.
package infrascout

import "time"

const Version = "0.1.0"

// Severity classifies change risk for operators.
// 专业名称: Severity；通俗解释: 变化有多危险。
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// Host is a machine resource.
type Host struct {
	ID                 string             `json:"id"`
	Hostname           string             `json:"hostname"`
	OS                 string             `json:"os"`
	Kernel             string             `json:"kernel"`
	Architecture       string             `json:"architecture"`
	CPU                CPUInfo            `json:"cpu"`
	Memory             MemoryInfo         `json:"memory"`
	Disks              []DiskInfo         `json:"disks"`
	NetworkInterfaces  []NetworkInterface `json:"network_interfaces"`
	CollectedAt        string             `json:"collected_at"`
}

type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

type MemoryInfo struct {
	TotalBytes int64 `json:"total_bytes"`
}

type DiskInfo struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	MountPoint string `json:"mount_point,omitempty"`
	FSType     string `json:"fs_type,omitempty"`
}

type NetworkInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	State     string   `json:"state,omitempty"`
}

// Process is a running program. PID is an attribute, never the stable ID.
type Process struct {
	ID               string `json:"id"`
	PID              int    `json:"pid"`
	Name             string `json:"name"`
	Executable       string `json:"executable"`
	CommandLine      string `json:"command_line"`
	WorkingDirectory string `json:"working_directory"`
	User             string `json:"user"`
	ParentPID        int    `json:"parent_pid"`
}

// ExposedLevel describes how reachable a listener is.
// 专业名称: ExposedLevel；通俗解释: 这个端口对外暴露到什么程度。
type ExposedLevel string

const (
	ExposedPublic    ExposedLevel = "public"    // 0.0.0.0 / :: / *
	ExposedLocalhost ExposedLevel = "localhost" // 127.0.0.1 / ::1
	ExposedPrivate   ExposedLevel = "private"   // other binds
	ExposedUnknown   ExposedLevel = "unknown"
)

// Endpoint is a listening network port associated with a process when possible.
type Endpoint struct {
	ID          string       `json:"id"`
	Protocol    string       `json:"protocol"`
	Address     string       `json:"address"`
	Port        int          `json:"port"`
	ProcessID   int          `json:"process_id,omitempty"`
	ProcessName string       `json:"process_name,omitempty"`
	ProcessUser string       `json:"process_user,omitempty"`
	ProcessRef  string       `json:"process_ref,omitempty"` // stable process resource id
	ExposedLevel ExposedLevel `json:"exposed_level"`
}

// DeploymentType / Source for Service.
type DeploymentType string

const (
	DeploySystemd DeploymentType = "systemd"
	DeployDocker  DeploymentType = "docker" // reserved; not collected in v0.1
	DeployUnknown DeploymentType = "unknown"
)

// Service is a managed unit (v0.1: systemd only).
type Service struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Type           string         `json:"type"` // e.g. service
	DeploymentType DeploymentType `json:"deployment_type"`
	Source         string         `json:"source"` // systemd | docker | unknown
	ActiveState    string         `json:"active_state,omitempty"`
	SubState       string         `json:"sub_state,omitempty"`
	ExecStart      string         `json:"exec_start,omitempty"`
	WorkingDirectory string      `json:"working_directory,omitempty"`
	User           string         `json:"user,omitempty"`
	MainPID        int            `json:"main_pid,omitempty"`
	Description    string         `json:"description,omitempty"`
}

// Relationship links two resources.
type Relationship struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Type       string   `json:"type"` // runs_on | listens_on
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Resource is the unified snapshot/inventory entry.
type Resource struct {
	Type     string     `json:"type"` // host | process | endpoint | service
	ID       string     `json:"id"`
	Host     *Host      `json:"host,omitempty"`
	Process  *Process   `json:"process,omitempty"`
	Endpoint *Endpoint  `json:"endpoint,omitempty"`
	Service  *Service   `json:"service,omitempty"`
}

// Inventory is the human-oriented resource list from `infrascout scan`.
type Inventory struct {
	CollectedAt   string         `json:"collected_at"`
	Hostname      string         `json:"hostname"`
	Summary       Summary        `json:"summary"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships"`
}

type Summary struct {
	Hosts      int `json:"hosts"`
	Processes  int `json:"processes"`
	Endpoints  int `json:"endpoints"`
	Services   int `json:"services"`
}

// Snapshot is a comparable state photo from `infrascout snapshot`.
type Snapshot struct {
	Timestamp     string         `json:"timestamp"`
	Hostname      string         `json:"hostname"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships"`
	// NoiseFields are ignored during attribute comparison.
	NoiseFields []string `json:"noise_fields"`
}

// DiffReport is the result of comparing two snapshots.
type DiffReport struct {
	ComparedAt   string       `json:"compared_at"`
	BaselineTime string       `json:"baseline_timestamp,omitempty"`
	CandidateTime string      `json:"candidate_timestamp,omitempty"`
	Added        []DiffItem   `json:"added"`
	Removed      []DiffItem   `json:"removed"`
	Changed      []ChangeItem `json:"changed"`
	HighestRisk  Severity     `json:"highest_risk"`
	Unchanged    int          `json:"unchanged_count"`
}

// DiffItem is an added or removed resource.
type DiffItem struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Summary  string   `json:"summary"`
	Severity Severity `json:"severity"`
}

// ChangeItem is a modified resource.
type ChangeItem struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Summary  string         `json:"summary"`
	Severity Severity       `json:"severity"`
	Before   map[string]any `json:"before,omitempty"`
	After    map[string]any `json:"after,omitempty"`
}

// FormatTime returns RFC3339 with timezone.
func FormatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// DefaultNoiseFields are volatile attributes not used for drift identity.
func DefaultNoiseFields() []string {
	return []string{"pid", "process_id", "parent_pid", "main_pid"}
}
