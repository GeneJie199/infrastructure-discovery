package infrascout

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Compare produces a DiffReport between baseline and candidate snapshots.
func Compare(baseline, candidate Snapshot) DiffReport {
	noise := candidate.NoiseFields
	if len(noise) == 0 {
		noise = baseline.NoiseFields
	}
	if len(noise) == 0 {
		noise = DefaultNoiseFields()
	}
	noiseSet := map[string]struct{}{}
	for _, n := range noise {
		noiseSet[n] = struct{}{}
	}

	baseIdx := indexResources(baseline.Resources)
	candIdx := indexResources(candidate.Resources)

	report := DiffReport{
		ComparedAt:    FormatTime(time.Now()),
		BaselineTime:  baseline.Timestamp,
		CandidateTime: candidate.Timestamp,
	}

	for id, cr := range candIdx {
		br, ok := baseIdx[id]
		if !ok {
			item := classifyAdded(cr)
			item.After = comparableMap(cr, noiseSet)
			report.Added = append(report.Added, item)
			continue
		}
		before := comparableMap(br, noiseSet)
		after := comparableMap(cr, noiseSet)
		if reflect.DeepEqual(before, after) {
			report.Unchanged++
			continue
		}
		diffBefore, diffAfter := mapDiff(before, after)
		ch := ChangeItem{
			ID:       id,
			Type:     cr.Type,
			Summary:  changeSummary(cr, diffBefore, diffAfter),
			Severity: classifyChanged(cr, diffBefore, diffAfter),
			Before:   diffBefore,
			After:    diffAfter,
		}
		report.Changed = append(report.Changed, ch)
	}

	for id, br := range baseIdx {
		if _, ok := candIdx[id]; ok {
			continue
		}
		item := classifyRemoved(br)
		item.Before = comparableMap(br, noiseSet)
		report.Removed = append(report.Removed, item)
	}

	report.HighestRisk = highest(
		severitiesFromAdded(report.Added),
		severitiesFromRemoved(report.Removed),
		severitiesFromChanged(report.Changed),
	)
	return report
}

func indexResources(rs []Resource) map[string]Resource {
	m := make(map[string]Resource, len(rs))
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

func comparableMap(r Resource, noise map[string]struct{}) map[string]any {
	m := resourceAttrs(r)
	for k := range noise {
		delete(m, k)
	}
	return m
}

func resourceAttrs(r Resource) map[string]any {
	m := map[string]any{}
	if r.Metadata != nil {
		for k, v := range r.Metadata {
			m[k] = v
		}
	}
	switch r.Type {
	case "host":
		if r.Host == nil {
			return m
		}
		h := r.Host
		m["hostname"] = h.Hostname
		m["os"] = h.OS
		m["kernel"] = h.Kernel
		m["architecture"] = h.Architecture
		m["cpu_model"] = h.CPU.Model
		m["cpu_cores"] = h.CPU.Cores
		m["memory_total_bytes"] = h.Memory.TotalBytes
	case "process":
		if r.Process == nil {
			return m
		}
		p := r.Process
		m["name"] = p.Name
		m["executable"] = p.Executable
		m["command_line"] = p.CommandLine
		m["working_directory"] = p.WorkingDirectory
		m["user"] = p.User
		m["pid"] = p.PID
		m["parent_pid"] = p.ParentPID
	case "endpoint":
		if r.Endpoint == nil {
			return m
		}
		e := r.Endpoint
		m["protocol"] = e.Protocol
		m["address"] = e.Address
		m["port"] = e.Port
		m["process_name"] = e.ProcessName
		m["process_ref"] = e.ProcessRef
		m["exposed_level"] = string(e.ExposedLevel)
		m["process_id"] = e.ProcessID
	case "service":
		if r.Service == nil {
			return m
		}
		s := r.Service
		m["name"] = s.Name
		m["type"] = s.Type
		m["deployment_type"] = string(s.DeploymentType)
		m["source"] = s.Source
		m["active_state"] = s.ActiveState
		m["sub_state"] = s.SubState
		m["exec_start"] = s.ExecStart
		m["working_directory"] = s.WorkingDirectory
		m["user"] = s.User
		m["main_pid"] = s.MainPID
		m["container_id"] = s.ContainerID
		m["image"] = s.Image
		m["status"] = s.Status
		m["ports"] = s.Ports
		m["compose_project"] = s.ComposeProject
		m["health"] = s.Health
		m["restart_count"] = s.RestartCount
		m["networks"] = s.Networks
		m["mounts"] = s.Mounts
	}
	return m
}

func mapDiff(before, after map[string]any) (map[string]any, map[string]any) {
	b := map[string]any{}
	a := map[string]any{}
	keys := map[string]struct{}{}
	for k := range before {
		keys[k] = struct{}{}
	}
	for k := range after {
		keys[k] = struct{}{}
	}
	for k := range keys {
		bv, bok := before[k]
		av, aok := after[k]
		if !bok {
			a[k] = av
			continue
		}
		if !aok {
			b[k] = bv
			continue
		}
		if !reflect.DeepEqual(bv, av) {
			b[k] = bv
			a[k] = av
		}
	}
	return b, a
}

func classifyAdded(r Resource) DiffItem {
	sum := fmt.Sprintf("added %s %s", r.Type, shortName(r))
	sev := SeverityInfo
	switch r.Type {
	case "endpoint":
		if r.Endpoint != nil && r.Endpoint.ExposedLevel == ExposedPublic {
			sev = SeverityCritical
			sum = fmt.Sprintf("new public listener %s:%d", r.Endpoint.Address, r.Endpoint.Port)
			if strings.EqualFold(r.Endpoint.ProcessUser, "root") {
				sum = fmt.Sprintf("A new root process exposes port %d", r.Endpoint.Port)
			}
		}
	case "service":
		sev = SeverityWarning
		sum = fmt.Sprintf("added service %s", shortName(r))
	case "process":
		if r.Process != nil && strings.EqualFold(r.Process.User, "root") {
			// root process alone is INFO unless tied to public endpoint (handled there)
			sev = SeverityInfo
		}
	}
	return DiffItem{ID: r.ID, Type: r.Type, Summary: sum, Severity: sev}
}

func classifyRemoved(r Resource) DiffItem {
	sum := fmt.Sprintf("removed %s %s", r.Type, shortName(r))
	sev := SeverityInfo
	switch r.Type {
	case "service":
		sev = SeverityWarning
		sum = fmt.Sprintf("systemd service disappeared: %s", shortName(r))
	case "endpoint":
		sev = SeverityWarning
		if r.Endpoint != nil {
			sum = fmt.Sprintf("removed port %d (%s)", r.Endpoint.Port, r.Endpoint.Protocol)
		}
	}
	return DiffItem{ID: r.ID, Type: r.Type, Summary: sum, Severity: sev}
}

func classifyChanged(r Resource, before, after map[string]any) Severity {
	if r.Type == "service" {
		if _, ok := after["exec_start"]; ok {
			return SeverityWarning
		}
		if _, ok := after["active_state"]; ok {
			return SeverityWarning
		}
	}
	if r.Type == "process" {
		if _, ok := after["executable"]; ok {
			return SeverityWarning
		}
		if _, ok := after["command_line"]; ok {
			return SeverityWarning
		}
	}
	if r.Type == "endpoint" {
		if v, ok := after["exposed_level"]; ok && v == string(ExposedPublic) {
			return SeverityCritical
		}
		if _, ok := after["process_ref"]; ok {
			return SeverityWarning
		}
	}
	return SeverityInfo
}

func changeSummary(r Resource, before, after map[string]any) string {
	name := shortName(r)
	parts := []string{}
	for k := range after {
		parts = append(parts, k+" changed")
	}
	if len(parts) == 0 {
		for k := range before {
			parts = append(parts, k+" removed")
		}
	}
	if len(parts) == 0 {
		return name + " changed"
	}
	return fmt.Sprintf("%s: %s", name, strings.Join(parts, ", "))
}

func shortName(r Resource) string {
	switch r.Type {
	case "host":
		if r.Host != nil {
			return r.Host.Hostname
		}
	case "process":
		if r.Process != nil {
			if r.Process.Executable != "" {
				return r.Process.Executable
			}
			return r.Process.Name
		}
	case "endpoint":
		if r.Endpoint != nil {
			return fmt.Sprintf("%s/%d", r.Endpoint.Protocol, r.Endpoint.Port)
		}
	case "service":
		if r.Service != nil {
			return r.Service.Name
		}
	}
	return r.ID
}

func severitiesFromAdded(items []DiffItem) []Severity {
	out := make([]Severity, len(items))
	for i, it := range items {
		out[i] = it.Severity
	}
	return out
}

func severitiesFromRemoved(items []DiffItem) []Severity {
	out := make([]Severity, len(items))
	for i, it := range items {
		out[i] = it.Severity
	}
	return out
}

func severitiesFromChanged(items []ChangeItem) []Severity {
	out := make([]Severity, len(items))
	for i, it := range items {
		out[i] = it.Severity
	}
	return out
}

func highest(groups ...[]Severity) Severity {
	rank := map[Severity]int{
		SeverityInfo: 1, SeverityWarning: 2, SeverityCritical: 3,
	}
	best := SeverityInfo
	bestRank := 1
	for _, g := range groups {
		for _, s := range g {
			if rank[s] > bestRank {
				best = s
				bestRank = rank[s]
			}
		}
	}
	return best
}
