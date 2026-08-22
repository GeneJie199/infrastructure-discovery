// Package infrascout is the reusable InfraScout discovery library.
// FleetScope Agent can import this package without depending on CLI code.
package infrascout

import "time"

var Version = "dev"

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
	ID                string             `json:"id"`
	Hostname          string             `json:"hostname"`
	OS                string             `json:"os"`
	Kernel            string             `json:"kernel"`
	Architecture      string             `json:"architecture"`
	CPU               CPUInfo            `json:"cpu"`
	Memory            MemoryInfo         `json:"memory"`
	Disks             []DiskInfo         `json:"disks"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
	CollectedAt       string             `json:"collected_at"`
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
	ID           string       `json:"id"`
	Protocol     string       `json:"protocol"`
	Address      string       `json:"address"`
	Port         int          `json:"port"`
	ProcessID    int          `json:"process_id,omitempty"`
	ProcessName  string       `json:"process_name,omitempty"`
	ProcessUser  string       `json:"process_user,omitempty"`
	ProcessRef   string       `json:"process_ref,omitempty"` // stable process resource id
	ExposedLevel ExposedLevel `json:"exposed_level"`
}

// DeploymentType / Source for Service.
type DeploymentType string

const (
	DeploySystemd DeploymentType = "systemd"
	DeployDocker  DeploymentType = "docker"
	DeployUnknown DeploymentType = "unknown"
)

// Service is a managed systemd unit or Docker container workload.
type Service struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Type             string           `json:"type"` // e.g. service
	DeploymentType   DeploymentType   `json:"deployment_type"`
	Source           string           `json:"source"` // systemd | docker | unknown
	ActiveState      string           `json:"active_state,omitempty"`
	SubState         string           `json:"sub_state,omitempty"`
	ExecStart        string           `json:"exec_start,omitempty"`
	WorkingDirectory string           `json:"working_directory,omitempty"`
	User             string           `json:"user,omitempty"`
	MainPID          int              `json:"main_pid,omitempty"`
	Description      string           `json:"description,omitempty"`
	ContainerID      string           `json:"container_id,omitempty"`
	Image            string           `json:"image,omitempty"`
	Status           string           `json:"status,omitempty"`
	Ports            string           `json:"ports,omitempty"`
	ComposeProject   string           `json:"compose_project,omitempty"`
	Health           string           `json:"health,omitempty"`
	RestartCount     int              `json:"restart_count,omitempty"`
	RestartPolicy    string           `json:"restart_policy,omitempty"`
	AutoStart        string           `json:"auto_start,omitempty"`
	UnitFile         string           `json:"unit_file,omitempty"`
	Networks         []string         `json:"networks,omitempty"`
	Mounts           []ContainerMount `json:"mounts,omitempty"`
}

type ContainerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"`
}

// Deployment records how and where a workload is installed and started.
type Deployment struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Method           string   `json:"method"` // systemd | docker | compose | process
	Location         string   `json:"location,omitempty"`
	Command          string   `json:"command,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	User             string   `json:"user,omitempty"`
	AutoStart        string   `json:"auto_start,omitempty"`
	RestartPolicy    string   `json:"restart_policy,omitempty"`
	RestartCommand   string   `json:"restart_command,omitempty"`
	ConfigFiles      []string `json:"config_files,omitempty"`
	ComposeProject   string   `json:"compose_project,omitempty"`
}

// Container is the typed Docker workload payload. Service remains populated
// for backward compatibility with v0.x consumers.
type Container struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	RuntimeID      string           `json:"runtime_id,omitempty"`
	Image          string           `json:"image"`
	Command        string           `json:"command,omitempty"`
	State          string           `json:"state,omitempty"`
	Health         string           `json:"health,omitempty"`
	RestartPolicy  string           `json:"restart_policy,omitempty"`
	ComposeProject string           `json:"compose_project,omitempty"`
	Networks       []string         `json:"networks,omitempty"`
	Mounts         []ContainerMount `json:"mounts,omitempty"`
}

type Database struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	Name        string   `json:"name"`
	ResourceID  string   `json:"resource_id"`
	EndpointIDs []string `json:"endpoint_ids,omitempty"`
	Local       bool     `json:"local"`
}

type Network struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

type Volume struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Source      string `json:"source"`
	Destination string `json:"destination,omitempty"`
	Mode        string `json:"mode,omitempty"`
}

// Evidence identifies the source behind a discovered fact.
type Evidence struct {
	ID         string `json:"id"`
	ResourceID string `json:"resource_id,omitempty"`
	Source     string `json:"source"`
	Detail     string `json:"detail,omitempty"`
}

// Observation is a timestamped fact emitted by a collector.
type Observation struct {
	ID         string         `json:"id"`
	ResourceID string         `json:"resource_id"`
	ObservedAt string         `json:"observed_at"`
	Facts      map[string]any `json:"facts,omitempty"`
	EvidenceID string         `json:"evidence_id,omitempty"`
}

// ChangeEvent gives history and external integrations a stable event shape.
type ChangeEvent struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	ResourceID string   `json:"resource_id"`
	Type       string   `json:"type"`
	Severity   Severity `json:"severity"`
	Summary    string   `json:"summary"`
	OccurredAt string   `json:"occurred_at"`
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
	Type       string         `json:"type"` // host | process | endpoint | service | deployment | database | docker.* | nginx.route
	ID         string         `json:"id"`
	Host       *Host          `json:"host,omitempty"`
	Process    *Process       `json:"process,omitempty"`
	Endpoint   *Endpoint      `json:"endpoint,omitempty"`
	Service    *Service       `json:"service,omitempty"`
	Deployment *Deployment    `json:"deployment,omitempty"`
	Container  *Container     `json:"container,omitempty"`
	Database   *Database      `json:"database,omitempty"`
	Network    *Network       `json:"network,omitempty"`
	Volume     *Volume        `json:"volume,omitempty"`
	Evidence   []Evidence     `json:"evidence,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Inventory is the human-oriented resource list from `infrascout scan`.
type Inventory struct {
	CollectedAt      string            `json:"collected_at"`
	Hostname         string            `json:"hostname"`
	Summary          Summary           `json:"summary"`
	Resources        []Resource        `json:"resources"`
	Relationships    []Relationship    `json:"relationships"`
	Warnings         []string          `json:"warnings,omitempty"`
	DetectedServices []DetectedService `json:"detected_services,omitempty"`
	Monitoring       MonitoringPlan    `json:"monitoring_plan"`
	NginxRoutes      []NginxRoute      `json:"nginx_routes,omitempty"`
	Applications     []Application     `json:"applications,omitempty"`
	Evidence         []Evidence        `json:"evidence,omitempty"`
	Observations     []Observation     `json:"observations,omitempty"`
}

type NginxRoute struct {
	SourceFile string `json:"source_file"`
	ServerName string `json:"server_name,omitempty"`
	Listen     string `json:"listen,omitempty"`
	Location   string `json:"location,omitempty"`
	Upstream   string `json:"upstream"`
}

// DetectedService is a deterministic classification of a discovered process or service.
type DetectedService struct {
	ResourceID string   `json:"resource_id" yaml:"resource_id"`
	Kind       string   `json:"kind" yaml:"kind"`
	Name       string   `json:"name" yaml:"name"`
	Source     string   `json:"source" yaml:"source"`
	Confidence float64  `json:"confidence" yaml:"confidence"`
	Endpoints  []string `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
}

// Application groups the facts that answer what a workload is, how it is
// deployed, what it exposes, and what it depends on.
type Application struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Source          string   `json:"source"`
	Confidence      float64  `json:"confidence"`
	Status          string   `json:"status,omitempty"`
	ResourceIDs     []string `json:"resource_ids"`
	DeploymentIDs   []string `json:"deployment_ids,omitempty"`
	EndpointIDs     []string `json:"endpoint_ids,omitempty"`
	DependencyIDs   []string `json:"dependency_ids,omitempty"`
	RestartCommand  string   `json:"restart_command,omitempty"`
	NeedsReview     bool     `json:"needs_review,omitempty"`
	EvidenceSummary []string `json:"evidence_summary,omitempty"`
}

type MonitoringPlan struct {
	Version         string                     `json:"version" yaml:"version"`
	GeneratedAt     string                     `json:"generated_at" yaml:"generated_at"`
	Hostname        string                     `json:"hostname" yaml:"hostname"`
	Recommendations []MonitoringRecommendation `json:"recommendations" yaml:"recommendations"`
	CoverageGaps    []string                   `json:"coverage_gaps,omitempty" yaml:"coverage_gaps,omitempty"`
}

type MonitoringRecommendation struct {
	ID         string            `json:"id" yaml:"id"`
	TargetID   string            `json:"target_id" yaml:"target_id"`
	Collector  string            `json:"collector" yaml:"collector"`
	Priority   string            `json:"priority" yaml:"priority"`
	Reason     string            `json:"reason" yaml:"reason"`
	Parameters map[string]string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

type Summary struct {
	Hosts        int `json:"hosts"`
	Processes    int `json:"processes"`
	Endpoints    int `json:"endpoints"`
	Services     int `json:"services"`
	Networks     int `json:"networks,omitempty"`
	Volumes      int `json:"volumes,omitempty"`
	Routes       int `json:"nginx_routes,omitempty"`
	Deployments  int `json:"deployments,omitempty"`
	Databases    int `json:"databases,omitempty"`
	Applications int `json:"applications,omitempty"`
}

// Snapshot is a comparable state photo from `infrascout snapshot`.
type Snapshot struct {
	Timestamp     string         `json:"timestamp"`
	Hostname      string         `json:"hostname"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships"`
	// NoiseFields are ignored during attribute comparison.
	NoiseFields []string `json:"noise_fields"`
	Warnings    []string `json:"warnings,omitempty"`
	State       string   `json:"state,omitempty"` // observed | approved | desired
}

// DiffReport is the result of comparing two snapshots.
type DiffReport struct {
	ComparedAt           string                      `json:"compared_at"`
	BaselineTime         string                      `json:"baseline_timestamp,omitempty"`
	CandidateTime        string                      `json:"candidate_timestamp,omitempty"`
	Added                []DiffItem                  `json:"added"`
	Removed              []DiffItem                  `json:"removed"`
	Changed              []ChangeItem                `json:"changed"`
	HighestRisk          Severity                    `json:"highest_risk"`
	BlockingRisk         Severity                    `json:"blocking_risk"`
	ClassificationCounts map[DriftClassification]int `json:"classification_counts,omitempty"`
	Unchanged            int                         `json:"unchanged_count"`
	Events               []ChangeEvent               `json:"events,omitempty"`
}

// DiffItem is an added or removed resource.
type DiffItem struct {
	ID              string              `json:"id"`
	Type            string              `json:"type"`
	Summary         string              `json:"summary"`
	Severity        Severity            `json:"severity"`
	Before          map[string]any      `json:"before,omitempty"`
	After           map[string]any      `json:"after,omitempty"`
	Fingerprint     string              `json:"fingerprint,omitempty"`
	Classification  DriftClassification `json:"classification,omitempty"`
	Decision        *DriftDecision      `json:"decision,omitempty"`
	DecisionExpired bool                `json:"decision_expired,omitempty"`
}

// ChangeItem is a modified resource.
type ChangeItem struct {
	ID              string              `json:"id"`
	Type            string              `json:"type"`
	Summary         string              `json:"summary"`
	Severity        Severity            `json:"severity"`
	Before          map[string]any      `json:"before,omitempty"`
	After           map[string]any      `json:"after,omitempty"`
	Fingerprint     string              `json:"fingerprint,omitempty"`
	Classification  DriftClassification `json:"classification,omitempty"`
	Decision        *DriftDecision      `json:"decision,omitempty"`
	DecisionExpired bool                `json:"decision_expired,omitempty"`
}

// FormatTime returns RFC3339 with timezone.
func FormatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// DefaultNoiseFields are volatile attributes not used for drift identity.
func DefaultNoiseFields() []string {
	return []string{"pid", "process_id", "parent_pid", "main_pid", "status", "health", "container_id", "restart_count"}
}
