package collect

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/host"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/net"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/process"
	"github.com/GeneJie199/infrastructure-discovery/internal/collect/systemd"
	"github.com/GeneJie199/infrastructure-discovery/internal/id"
	"github.com/GeneJie199/infrastructure-discovery/internal/model"
	"github.com/GeneJie199/infrastructure-discovery/internal/redact"
)

// Scan runs INF-002..INF-004 collectors and builds inventory + snapshot (INF-001).
func Scan(opts Options) (*Result, error) {
	now := time.Now()
	capturedAt := model.FormatTime(now)

	hostInfo, procs, listeners, units, err := gather(opts)
	if err != nil {
		return nil, err
	}

	hostname := hostInfo.Hostname
	hostRID := id.Host(hostname)
	source := model.Source{
		Product:    "infra-discovery",
		InstanceID: opts.InstanceID,
		Version:    opts.Version,
	}
	if source.InstanceID == "" {
		source.InstanceID = "infra-discovery-" + hostname
	}

	var resources []model.Resource
	var relationships []model.Relationship

	hostRes := model.Resource{
		SpecVersion:  model.SpecVersion,
		ResourceID:   hostRID,
		ResourceType: "host",
		DisplayName:  hostname,
		Attributes: map[string]any{
			"os":          "linux",
			"osName":      hostInfo.OSName,
			"osVersion":   hostInfo.OSVersion,
			"osId":        hostInfo.OSID,
			"kernel":      hostInfo.Kernel,
			"arch":        hostInfo.Arch,
			"cpuModel":    hostInfo.CPUModel,
			"cpuCores":    hostInfo.CPUCores,
			"memoryBytes": hostInfo.MemoryBytes,
			"disks":       hostInfo.Disks,
			"nics":        hostInfo.NICs,
		},
		LastSeenAt: capturedAt,
	}
	resources = append(resources, hostRes)

	// Index processes by PID for listener association.
	procByPID := map[int]process.Info{}
	for _, p := range procs {
		procByPID[p.PID] = p
		exe := p.Exe
		if exe == "" {
			exe = p.Comm
		}
		rid := id.ProcessBin(hostname, exe)
		resources = append(resources, model.Resource{
			SpecVersion:      model.SpecVersion,
			ResourceID:       rid,
			ResourceType:     "process.bin",
			DisplayName:      displayProcess(p),
			ParentResourceID: hostRID,
			Attributes: map[string]any{
				"pid":       p.PID,
				"ppid":      p.PPID,
				"user":      p.User,
				"uid":       p.UID,
				"comm":      p.Comm,
				"cmdline":   redact.CommandLine(p.Cmdline),
				"exe":       p.Exe,
				"cwd":       p.Cwd,
				"state":     p.State,
				"startedAt": model.FormatTime(p.StartedAt),
			},
			LastSeenAt: capturedAt,
		})
		relationships = append(relationships, model.Relationship{
			SpecVersion:    model.SpecVersion,
			RelationshipID: id.NewRelationshipID(),
			Type:           "runs_on",
			From:           rid,
			To:             hostRID,
			ObservedAt:     capturedAt,
		})
	}

	for _, l := range listeners {
		rid := id.NetListener(hostname, l.Proto, l.Addr, l.Port)
		attrs := map[string]any{
			"proto": l.Proto,
			"addr":  l.Addr,
			"port":  l.Port,
			"inode": l.Inode,
		}
		if l.PID > 0 {
			attrs["pid"] = l.PID
		}
		if l.ProcessExe != "" {
			attrs["processExe"] = l.ProcessExe
		}
		resources = append(resources, model.Resource{
			SpecVersion:      model.SpecVersion,
			ResourceID:       rid,
			ResourceType:     "net.listener",
			DisplayName:      fmt.Sprintf("%s://%s:%d", l.Proto, l.Addr, l.Port),
			ParentResourceID: hostRID,
			Attributes:       attrs,
			LastSeenAt:       capturedAt,
		})
		relationships = append(relationships, model.Relationship{
			SpecVersion:    model.SpecVersion,
			RelationshipID: id.NewRelationshipID(),
			Type:           "listens_on",
			From:           hostRID,
			To:             rid,
			ObservedAt:     capturedAt,
		})
		if l.PID > 0 {
			if p, ok := procByPID[l.PID]; ok {
				exe := p.Exe
				if exe == "" {
					exe = p.Comm
				}
				procRID := id.ProcessBin(hostname, exe)
				relationships = append(relationships, model.Relationship{
					SpecVersion:    model.SpecVersion,
					RelationshipID: id.NewRelationshipID(),
					Type:           "listens_on",
					From:           procRID,
					To:             rid,
					ObservedAt:     capturedAt,
					Attributes: map[string]any{
						"pid": l.PID, // association hint; filtered in resource attr diffs via noisePolicy
					},
				})
			}
		}
	}

	for _, u := range units {
		rid := id.SystemdService(hostname, u.Name)
		attrs := map[string]any{
			"unit":          u.Name,
			"loadState":     u.LoadState,
			"activeState":   u.ActiveState,
			"subState":      u.SubState,
			"description":   u.Description,
			"fragmentPath":  u.FragmentPath,
			"unitFileState": u.UnitFileState,
		}
		if u.MainPID > 0 {
			attrs["mainPID"] = u.MainPID
		}
		display := u.Name
		if u.Description != "" {
			display = u.Description
		}
		resources = append(resources, model.Resource{
			SpecVersion:      model.SpecVersion,
			ResourceID:       rid,
			ResourceType:     "svc.systemd",
			DisplayName:      display,
			ParentResourceID: hostRID,
			Attributes:       attrs,
			LastSeenAt:       capturedAt,
		})
		relationships = append(relationships, model.Relationship{
			SpecVersion:    model.SpecVersion,
			RelationshipID: id.NewRelationshipID(),
			Type:           "runs_on",
			From:           rid,
			To:             hostRID,
			ObservedAt:     capturedAt,
		})
	}

	resources = dedupeResources(resources)
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ResourceID < resources[j].ResourceID
	})

	snap := model.Snapshot{
		SpecVersion: model.SpecVersion,
		SnapshotID:  id.NewSnapshotID(),
		CapturedAt:  capturedAt,
		Source:      source,
		Context:     opts.Context,
		NoisePolicy: model.NoisePolicy{
			FilteredFields: append([]string{}, model.DefaultNoiseFilteredFields...),
			Notes:          "Exclude PID and process start time from comparison",
		},
		Resources:     resources,
		Relationships: relationships,
	}

	inv := model.Inventory{
		SpecVersion:  model.SpecVersion,
		InventoryID:  id.NewInventoryID(),
		CapturedAt:   capturedAt,
		Source:       source,
		Context:      opts.Context,
		HostResource: hostRID,
		Resources:    toInventoryResources(resources),
	}

	return &Result{Inventory: inv, Snapshot: snap}, nil
}

func gather(opts Options) (*host.Info, []process.Info, []net.Listener, []systemd.Unit, error) {
	if opts.FixtureRoot != "" {
		root := opts.FixtureRoot
		h, err := host.ParseFromRoot(root)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("host fixture: %w", err)
		}
		procs, err := process.ParseFromRoot(root)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("process fixture: %w", err)
		}
		listeners, err := net.ParseFromRoot(root)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("net fixture: %w", err)
		}
		units, err := systemd.ParseFromRoot(root)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("systemd fixture: %w", err)
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

func displayProcess(p process.Info) string {
	if p.Exe != "" {
		return filepath.Base(p.Exe)
	}
	if p.Comm != "" {
		return p.Comm
	}
	return fmt.Sprintf("pid-%d", p.PID)
}

func dedupeResources(in []model.Resource) []model.Resource {
	seen := map[string]model.Resource{}
	for _, r := range in {
		if prev, ok := seen[r.ResourceID]; ok {
			// Merge: keep richer attributes; prefer non-empty fields.
			seen[r.ResourceID] = mergeResource(prev, r)
			continue
		}
		seen[r.ResourceID] = r
	}
	out := make([]model.Resource, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	return out
}

func mergeResource(a, b model.Resource) model.Resource {
	if a.Attributes == nil {
		a.Attributes = map[string]any{}
	}
	for k, v := range b.Attributes {
		if _, ok := a.Attributes[k]; !ok {
			a.Attributes[k] = v
		}
	}
	return a
}

func toInventoryResources(resources []model.Resource) []model.Resource {
	out := make([]model.Resource, 0, len(resources))
	for _, r := range resources {
		cp := r
		if cp.Attributes != nil {
			attrs := map[string]any{}
			for k, v := range cp.Attributes {
				if k == "pid" || k == "startedAt" || k == "mainPID" {
					continue
				}
				attrs[k] = v
			}
			cp.Attributes = attrs
		}
		out = append(out, cp)
	}
	return out
}
