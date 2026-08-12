package infrascout

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/docker"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/host"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/net"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/process"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/systemd"
	"github.com/GeneJie199/infrastructure-discovery/internal/configscan"
	"github.com/GeneJie199/infrastructure-discovery/internal/errs"
	"github.com/GeneJie199/infrastructure-discovery/internal/redact"
)

// ScanOptions configures discovery.
type ScanOptions struct {
	// FixtureRoot reads a fake proc/systemd tree (for tests / non-Linux).
	FixtureRoot string
	// NginxRoot overrides the nginx configuration directory. Defaults to /etc/nginx on live Linux.
	NginxRoot string
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

	h, procs, listeners, units, containers, warnings, err := gather(opts.FixtureRoot)
	if err != nil {
		return nil, err
	}

	hostname := h.Hostname
	hostID := HostID(hostname)
	excludedPIDs := currentProcessTreePIDs(procs, os.Getpid())
	procs = excludeProcesses(procs, excludedPIDs)
	listeners = excludeListeners(listeners, excludedPIDs)

	hostRes := Resource{
		Type: "host",
		ID:   hostID,
		Host: &Host{
			ID:                hostID,
			Hostname:          hostname,
			OS:                fmt.Sprintf("%s %s", h.OSName, h.OSVersion),
			Kernel:            h.Kernel,
			Architecture:      h.Arch,
			CPU:               CPUInfo{Model: h.CPUModel, Cores: h.CPUCores},
			Memory:            MemoryInfo{TotalBytes: h.MemoryBytes},
			Disks:             mapDisks(h.Disks),
			NetworkInterfaces: mapNICs(h.NICs),
			CollectedAt:       at,
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
			CommandLine:      redact.CommandLine(p.Cmdline),
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
			ExecStart:        redact.CommandLine(u.ExecStart),
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

	for _, c := range containers {
		sid := ContainerID(hostname, c.Name)
		svc := &Service{
			ID: sid, Name: c.Name, Type: "container", DeploymentType: DeployDocker,
			Source: "docker", ActiveState: c.State, SubState: c.Status,
			ExecStart: redact.CommandLine(c.Command), ContainerID: c.ID,
			Image: c.Image, Status: c.Status, Ports: c.Ports,
			ComposeProject: composeProject(c.Labels),
			Health:         c.Health, RestartCount: c.RestartCount, Networks: c.Networks,
		}
		for _, m := range c.Mounts {
			svc.Mounts = append(svc.Mounts, ContainerMount{Type: m.Type, Source: m.Source, Destination: m.Destination, Mode: m.Mode})
		}
		resources = append(resources, Resource{Type: "service", ID: sid, Service: svc})
		rels = append(rels, Relationship{
			Source: sid, Target: hostID, Type: "runs_on", Confidence: 1.0,
			Evidence: []string{"docker ps"},
		})
		for _, name := range c.Networks {
			nid := DockerNetworkID(hostname, name)
			resources = append(resources, Resource{Type: "docker.network", ID: nid, Metadata: map[string]any{"name": name}})
			rels = append(rels, Relationship{Source: sid, Target: nid, Type: "connected_to", Confidence: 1, Evidence: []string{"docker inspect"}})
		}
		for _, mount := range c.Mounts {
			vid := DockerVolumeID(hostname, mount.Source)
			resources = append(resources, Resource{Type: "docker.volume", ID: vid, Metadata: map[string]any{"type": mount.Type, "source": mount.Source, "destination": mount.Destination, "mode": mount.Mode}})
			rels = append(rels, Relationship{Source: sid, Target: vid, Type: "mounts", Confidence: 1, Evidence: []string{"docker inspect"}})
		}
	}

	nginxRoot := opts.NginxRoot
	if nginxRoot == "" {
		if opts.FixtureRoot != "" {
			nginxRoot = filepath.Join(opts.FixtureRoot, "nginx")
		} else {
			nginxRoot = "/etc/nginx"
		}
	}
	nginxRoutes := []NginxRoute{}
	if routes, nginxWarnings, nginxErr := configscan.ParseNginx(nginxRoot); nginxErr != nil {
		warnings = append(warnings, "nginx config: "+nginxErr.Error())
	} else {
		for _, route := range routes {
			clean := NginxRoute{SourceFile: route.SourceFile, ServerName: route.ServerName, Listen: route.Listen, Location: route.Location, Upstream: redact.CommandLine(route.Upstream)}
			nginxRoutes = append(nginxRoutes, clean)
			routeID := NginxRouteID(hostname, clean.SourceFile, clean.ServerName, clean.Listen, clean.Location)
			resources = append(resources, Resource{Type: "nginx.route", ID: routeID, Metadata: map[string]any{
				"source_file": clean.SourceFile, "server_name": clean.ServerName, "listen": clean.Listen,
				"location": clean.Location, "upstream": clean.Upstream,
			}})
			rels = append(rels, Relationship{Source: routeID, Target: hostID, Type: "configured_on", Confidence: 1, Evidence: []string{clean.SourceFile}})
		}
		warnings = append(warnings, nginxWarnings...)
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
		case "docker.network":
			sum.Networks++
		case "docker.volume":
			sum.Volumes++
		case "nginx.route":
			sum.Routes++
		}
	}

	inv := Inventory{
		CollectedAt:   at,
		Hostname:      hostname,
		Summary:       sum,
		Resources:     resources,
		Relationships: rels,
		Warnings:      warnings,
		NginxRoutes:   nginxRoutes,
	}
	AnalyzeInventory(&inv)
	snap := Snapshot{
		Timestamp:     at,
		Hostname:      hostname,
		Resources:     cloneResourcesForSnapshot(resources),
		Relationships: rels,
		NoiseFields:   DefaultNoiseFields(),
		Warnings:      warnings,
	}

	return &ScanResult{Inventory: inv, Snapshot: snap}, nil
}

func gather(fixture string) (*host.Info, []process.Info, []net.Listener, []systemd.Unit, []docker.Container, []string, error) {
	if fixture != "" {
		h, err := host.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		procs, err := process.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		listeners, err := net.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		units, err := systemd.ParseFromRoot(fixture)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		return h, procs, listeners, units, nil, nil, nil
	}
	h, err := host.Collect()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	procs, err := process.Collect()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	listeners, err := net.Collect()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	units, err := systemd.Collect()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	containers, dockerErr := docker.Collect()
	var warnings []string
	if dockerErr != nil {
		warnings = append(warnings, dockerErr.Error())
	}
	return h, procs, listeners, units, containers, warnings, nil
}

func composeProject(labels string) string {
	for _, label := range strings.Split(labels, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(label), "=")
		if ok && key == "com.docker.compose.project" {
			return value
		}
	}
	return ""
}

func currentProcessTreePIDs(procs []process.Info, pid int) map[int]struct{} {
	byPID := make(map[int]process.Info, len(procs))
	for _, proc := range procs {
		byPID[proc.PID] = proc
	}
	excluded := map[int]struct{}{}
	for pid > 1 {
		proc, ok := byPID[pid]
		if !ok {
			break
		}
		excluded[pid] = struct{}{}
		pid = proc.PPID
	}
	return excluded
}

func excludeProcesses(procs []process.Info, excluded map[int]struct{}) []process.Info {
	result := make([]process.Info, 0, len(procs))
	for _, proc := range procs {
		if _, skip := excluded[proc.PID]; skip {
			continue
		}
		// Kernel worker threads churn constantly and do not represent deployed
		// application state. They are children of kthreadd (PID 2) and have no
		// userspace command line.
		if proc.PID == 2 || (proc.PPID == 2 && proc.Cmdline == "") {
			continue
		}
		result = append(result, proc)
	}
	return result
}

func excludeListeners(listeners []net.Listener, excluded map[int]struct{}) []net.Listener {
	result := make([]net.Listener, 0, len(listeners))
	for _, listener := range listeners {
		if _, skip := excluded[listener.PID]; !skip {
			result = append(result, listener)
		}
	}
	return result
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
