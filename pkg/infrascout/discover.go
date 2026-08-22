package infrascout

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		deploymentID := DeploymentID(hostname, "systemd", u.Name)
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
			RestartPolicy:    u.Restart,
			AutoStart:        u.UnitFileState,
			UnitFile:         u.FragmentPath,
		}
		resources = append(resources,
			Resource{Type: "service", ID: sid, Service: svc, Evidence: []Evidence{{ID: "evidence:" + sanitizeID(sid) + ":systemd", ResourceID: sid, Source: "systemctl", Detail: u.FragmentPath}}},
			Resource{Type: "deployment", ID: deploymentID, Deployment: &Deployment{ID: deploymentID, Name: u.Name, Method: "systemd", Location: u.FragmentPath, Command: svc.ExecStart, WorkingDirectory: svc.WorkingDirectory, User: svc.User, AutoStart: svc.AutoStart, RestartPolicy: svc.RestartPolicy, RestartCommand: "systemctl restart " + u.Name, ConfigFiles: nonEmptyStrings(u.FragmentPath)}},
		)
		rels = append(rels, Relationship{
			Source:     sid,
			Target:     hostID,
			Type:       "runs_on",
			Confidence: 1.0,
			Evidence:   []string{"systemctl"},
		})
		rels = append(rels,
			Relationship{Source: sid, Target: deploymentID, Type: "deployed_as", Confidence: 1, Evidence: []string{"systemctl show"}},
			Relationship{Source: deploymentID, Target: hostID, Type: "runs_on", Confidence: 1, Evidence: []string{"systemctl show"}},
		)
	}

	for _, c := range containers {
		sid := ContainerID(hostname, c.Name)
		deploymentName := c.Name
		deploymentMethod := "docker"
		if project := composeProject(c.Labels); project != "" {
			deploymentName = project
			deploymentMethod = "compose"
		}
		deploymentID := DeploymentID(hostname, deploymentMethod, deploymentName)
		svc := &Service{
			ID: sid, Name: c.Name, Type: "container", DeploymentType: DeployDocker,
			Source: "docker", ActiveState: c.State, SubState: c.Status,
			ExecStart: redact.CommandLine(c.Command), ContainerID: c.ID,
			Image: c.Image, Status: c.Status, Ports: c.Ports,
			ComposeProject: composeProject(c.Labels),
			Health:         c.Health, RestartCount: c.RestartCount, RestartPolicy: c.RestartPolicy, AutoStart: dockerAutoStart(c.RestartPolicy), Networks: c.Networks,
		}
		for _, m := range c.Mounts {
			svc.Mounts = append(svc.Mounts, ContainerMount{Type: m.Type, Source: m.Source, Destination: m.Destination, Mode: m.Mode})
		}
		container := &Container{ID: sid, Name: c.Name, RuntimeID: c.ID, Image: c.Image, Command: svc.ExecStart, State: c.State, Health: c.Health, RestartPolicy: c.RestartPolicy, ComposeProject: svc.ComposeProject, Networks: append([]string(nil), c.Networks...), Mounts: append([]ContainerMount(nil), svc.Mounts...)}
		resources = append(resources,
			Resource{Type: "service", ID: sid, Service: svc, Container: container, Evidence: []Evidence{{ID: "evidence:" + sanitizeID(sid) + ":docker", ResourceID: sid, Source: "docker inspect", Detail: c.Image}}},
			Resource{Type: "deployment", ID: deploymentID, Deployment: &Deployment{ID: deploymentID, Name: deploymentName, Method: deploymentMethod, Command: svc.ExecStart, AutoStart: svc.AutoStart, RestartPolicy: svc.RestartPolicy, RestartCommand: "docker restart " + c.Name, ComposeProject: svc.ComposeProject}},
		)
		rels = append(rels, Relationship{
			Source: sid, Target: hostID, Type: "runs_on", Confidence: 1.0,
			Evidence: []string{"docker ps"},
		})
		rels = append(rels,
			Relationship{Source: sid, Target: deploymentID, Type: "deployed_as", Confidence: 1, Evidence: []string{"docker inspect"}},
			Relationship{Source: deploymentID, Target: hostID, Type: "runs_on", Confidence: 1, Evidence: []string{"docker inspect"}},
		)
		for _, name := range c.Networks {
			nid := DockerNetworkID(hostname, name)
			resources = append(resources, Resource{Type: "docker.network", ID: nid, Network: &Network{ID: nid, Name: name}, Metadata: map[string]any{"name": name}})
			rels = append(rels, Relationship{Source: sid, Target: nid, Type: "connected_to", Confidence: 1, Evidence: []string{"docker inspect"}})
		}
		for _, mount := range c.Mounts {
			vid := DockerVolumeID(hostname, mount.Source)
			resources = append(resources, Resource{Type: "docker.volume", ID: vid, Volume: &Volume{ID: vid, Name: pathBase(mount.Source), Kind: mount.Type, Source: mount.Source, Destination: mount.Destination, Mode: mount.Mode}, Metadata: map[string]any{"type": mount.Type, "source": mount.Source, "destination": mount.Destination, "mode": mount.Mode}})
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
			if target := matchUpstreamEndpoint(clean.Upstream, resources); target != "" {
				rels = append(rels, Relationship{Source: routeID, Target: target, Type: "proxies_to", Confidence: .95, Evidence: []string{clean.SourceFile + ": proxy_pass " + clean.Upstream}})
			}
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

	inv := Inventory{
		CollectedAt:   at,
		Hostname:      hostname,
		Summary:       summarizeResources(resources),
		Resources:     resources,
		Relationships: rels,
		Warnings:      warnings,
		NginxRoutes:   nginxRoutes,
	}
	AnalyzeInventory(&inv)
	inv.Resources = dedupeResources(inv.Resources)
	sort.Slice(inv.Resources, func(i, j int) bool { return inv.Resources[i].ID < inv.Resources[j].ID })
	sort.Slice(inv.Relationships, func(i, j int) bool {
		return RelationshipID(inv.Relationships[i]) < RelationshipID(inv.Relationships[j])
	})
	inv.Summary = summarizeResources(inv.Resources)
	inv.Summary.Applications = len(inv.Applications)
	inv.Evidence, inv.Observations = buildEvidence(inv.Resources, at)
	snap := Snapshot{
		Timestamp:     at,
		Hostname:      hostname,
		Resources:     cloneResourcesForSnapshot(inv.Resources),
		Relationships: append([]Relationship(nil), inv.Relationships...),
		NoiseFields:   DefaultNoiseFields(),
		Warnings:      warnings,
		State:         "observed",
	}

	return &ScanResult{Inventory: inv, Snapshot: snap}, nil
}

func dockerAutoStart(policy string) string {
	if policy == "" || policy == "no" {
		return "disabled"
	}
	return "enabled"
}

func nonEmptyStrings(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func matchUpstreamEndpoint(upstream string, resources []Resource) string {
	value := strings.TrimSpace(upstream)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.Port() == "" {
		return ""
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.Trim(parsed.Hostname(), "[]"))
	for _, resource := range resources {
		if resource.Endpoint != nil && resource.Endpoint.Port == port && upstreamMatchesListener(host, resource.Endpoint.Address) {
			return resource.ID
		}
	}
	return ""
}

func upstreamMatchesListener(host, listener string) bool {
	listener = strings.ToLower(strings.Trim(strings.TrimSpace(listener), "[]"))
	if host == listener {
		return true
	}
	localHost := host == "localhost" || host == "127.0.0.1" || host == "::1"
	wildcard := listener == "0.0.0.0" || listener == "::" || listener == "*"
	return localHost && (wildcard || listener == "localhost" || listener == "127.0.0.1" || listener == "::1")
}

func summarizeResources(resources []Resource) Summary {
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
		case "deployment":
			sum.Deployments++
		case "database":
			sum.Databases++
		}
	}
	return sum
}

func buildEvidence(resources []Resource, observedAt string) ([]Evidence, []Observation) {
	evidence := []Evidence{}
	observations := []Observation{}
	for _, resource := range resources {
		for _, item := range resource.Evidence {
			evidence = append(evidence, item)
			observations = append(observations, Observation{ID: "observation:" + sanitizeID(resource.ID), ResourceID: resource.ID, ObservedAt: observedAt, Facts: map[string]any{"type": resource.Type}, EvidenceID: item.ID})
		}
	}
	return evidence, observations
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
	units, systemdErr := systemd.Collect()
	containers, dockerErr := docker.Collect()
	var warnings []string
	if systemdErr != nil {
		warnings = append(warnings, "systemd: "+systemdErr.Error())
	}
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
