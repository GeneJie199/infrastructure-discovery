package infrascout

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/host"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/net"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/process"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/systemd"
	"github.com/GeneJie199/infrastructure-discovery/internal/errs"
)

// ScanOptions configures discovery.
type ScanOptions struct {
	// FixtureRoot reads a fake proc/systemd tree (for tests / non-Linux).
	FixtureRoot string
}

// ScanResult holds both inventory and snapshot from one discovery pass.
type ScanResult struct {
	Inventory Inventory
	Snapshot  Snapshot
}

// Discover runs collectors and builds Inventory + Snapshot.
func Discover(opts ScanOptions) (*ScanResult, error) {
	now := time.Now()
	at := FormatTime(now)

	h, procs, listeners, units, err := gather(opts.FixtureRoot)
	if err != nil {
		return nil, err
	}

	hostname := h.Hostname
	hostID := HostID(hostname)

	hostRes := Resource{
		Type: "host",
		ID:   hostID,
		Host: &Host{
			ID:           hostID,
			Hostname:     hostname,
			OS:           fmt.Sprintf("%s %s", h.OSName, h.OSVersion),
			Kernel:       h.Kernel,
			Architecture: h.Arch,
			CPU:          CPUInfo{Model: h.CPUModel, Cores: h.CPUCores},
			Memory:       MemoryInfo{TotalBytes: h.MemoryBytes},
			Disks:        mapDisks(h.Disks),
			NetworkInterfaces: mapNICs(h.NICs),
			CollectedAt:  at,
		},
	}

	procByPID := map[int]process.Info{}
	var resources []Resource
	var rels []Relationship
	resources = append(resources, hostRes)

	for _, p := range procs {
		procByPID[p.PID] = p
		exe := p.Exe
		if exe == "" {
			exe = p.Comm
		}
		pid := ProcessID(hostname, p.Comm, exe, p.Cwd)
		pr := &Process{
			ID:               pid,
			PID:              p.PID,
			Name:             p.Comm,
			Executable:       p.Exe,
			CommandLine:      p.Cmdline,
			WorkingDirectory: p.Cwd,
			User:             p.User,
			ParentPID:        p.PPID,
		}
		resources = append(resources, Resource{Type: "process", ID: pid, Process: pr})
		rels = append(rels, Relationship{
			Source:     pid,
			Target:     hostID,
			Type:       "runs_on",
			Confidence: 1.0,
			Evidence:   []string{"procfs"},
		})
	}

	for _, l := range listeners {
		eid := EndpointID(hostname, l.Proto, l.Addr, l.Port)
		ep := &Endpoint{
			ID:           eid,
			Protocol:     l.Proto,
			Address:      l.Addr,
			Port:         l.Port,
			ProcessID:    l.PID,
			ExposedLevel: ClassifyExposed(l.Addr),
		}
		var procRef string
		if l.PID > 0 {
			if p, ok := procByPID[l.PID]; ok {
				ep.ProcessName = p.Comm
				ep.ProcessUser = p.User
				exe := p.Exe
				if exe == "" {
					exe = p.Comm
				}
				procRef = ProcessID(hostname, p.Comm, exe, p.Cwd)
				ep.ProcessRef = procRef
			} else if l.ProcessExe != "" {
				ep.ProcessName = pathBase(l.ProcessExe)
				procRef = ProcessID(hostname, pathBase(l.ProcessExe), l.ProcessExe, "")
				ep.ProcessRef = procRef
			}
		}
		resources = append(resources, Resource{Type: "endpoint", ID: eid, Endpoint: ep})
		rels = append(rels, Relationship{
			Source:     hostID,
			Target:     eid,
			Type:       "listens_on",
			Confidence: 1.0,
			Evidence:   []string{"procfs:/proc/net"},
		})
		if procRef != "" {
			rels = append(rels, Relationship{
				Source:     procRef,
				Target:     eid,
				Type:       "listens_on",
				Confidence: 0.9,
				Evidence:   []string{fmt.Sprintf("socket inode mapped to pid %d", l.PID)},
			})
		}
	}

	for _, u := range units {
		sid := ServiceID(hostname, u.Name)
		svc := &Service{
			ID:               sid,
			Name:             u.Name,
			Type:             "service",
			DeploymentType:   DeploySystemd,
			Source:           "systemd",
			ActiveState:      u.ActiveState,
			SubState:         u.SubState,
			ExecStart:        u.ExecStart,
			WorkingDirectory: u.WorkingDirectory,
			User:             u.User,
			MainPID:          u.MainPID,
			Description:      u.Description,
		}
		resources = append(resources, Resource{Type: "service", ID: sid, Service: svc})
		rels = append(rels, Relationship{
			Source:     sid,
			Target:     hostID,
			Type:       "runs_on",
			Confidence: 1.0,
			Evidence:   []string{"systemctl"},
		})
	}

	resources = dedupeResources(resources)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].Type != rels[j].Type {
			return rels[i].Type < rels[j].Type
		}
		if rels[i].Source != rels[j].Source {
			return rels[i].Source < rels[j].Source
		}
		return rels[i].Target < rels[j].Target
	})

	sum := Summary{}
	for _, r := range resources {
		switch r.Type {
		case "host":
			sum.Hosts++
		case "process":
			sum.Processes++
		case "endpoint":
			sum.Endpoints++
		case "service":
			sum.Services++
		}
	}

	inv := Inventory{
		CollectedAt:   at,
		Hostname:      hostname,
		Summary:       sum,
		Resources:     resources,
		Relationships: rels,
	}
	snap := Snapshot{
		Timestamp:     at,
		Hostname:      hostname,
		Resources:     cloneResourcesForSnapshot(resources),
		Relationships: rels,
		NoiseFields:   DefaultNoiseFields(),
	}

	return &ScanResult{Inventory: inv, Snapshot: snap}, nil
}

func gather(fixture string) (*host.Info, []process.Info, []net.Listener, []systemd.Unit, error) {
	if fixture != "" {
		h, err := host.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		procs, err := process.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		listeners, err := net.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		units, err := systemd.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return h, procs, listeners, units, nil
	}
	h, err := host.Collect()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	procs, err := process.Collect()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	listeners, err := net.Collect()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	units, err := systemd.Collect()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return h, procs, listeners, units, nil
}

// ErrUnsupported is returned on non-Linux without --fixture.
var ErrUnsupported = errs.ErrUnsupported

func mapDisks(in []host.Disk) []DiskInfo {
	out := make([]DiskInfo, 0, len(in))
	for _, d := range in {
		out = append(out, DiskInfo{
			Name: d.Name, SizeBytes: d.SizeBytes, MountPoint: d.MountPoint, FSType: d.FSType,
		})
	}
	return out
}

func mapNICs(in []host.NIC) []NetworkInterface {
	out := make([]NetworkInterface, 0, len(in))
	for _, n := range in {
		out = append(out, NetworkInterface{
			Name: n.Name, MAC: n.MAC, Addresses: n.Addresses, State: n.State,
		})
	}
	return out
}

func pathBase(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dedupeResources(in []Resource) []Resource {
	seen := map[string]Resource{}
	order := []string{}
	for _, r := range in {
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = r
		order = append(order, r.ID)
	}
	out := make([]Resource, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id])
	}
	return out
}

func cloneResourcesForSnapshot(in []Resource) []Resource {
	// Same content; snapshot keeps volatile attrs but Diff ignores NoiseFields.
	out := make([]Resource, len(in))
	copy(out, in)
	return out
}
