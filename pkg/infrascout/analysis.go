package infrascout

import (
	"fmt"
	"sort"
	"strings"
)

// AnalyzeInventory recognizes common infrastructure products and produces a deterministic monitoring plan.
func AnalyzeInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	endpoints := map[string][]string{}
	for _, r := range inv.Resources {
		if r.Endpoint != nil && r.Endpoint.ProcessRef != "" {
			endpoints[r.Endpoint.ProcessRef] = append(endpoints[r.Endpoint.ProcessRef], fmt.Sprintf("%s/%s:%d", r.Endpoint.Protocol, r.Endpoint.Address, r.Endpoint.Port))
		}
	}
	// The separate loop keeps classification independent from discovery ordering.
	detected := []DetectedService{}
	seen := map[string]bool{}
	for _, r := range inv.Resources {
		name, source := "", ""
		if r.Process != nil {
			name = strings.Join([]string{r.Process.Name, r.Process.Executable, r.Process.CommandLine}, " ")
			source = "process"
		}
		if r.Service != nil {
			name = strings.Join([]string{r.Service.Name, r.Service.Image, r.Service.ExecStart}, " ")
			source = r.Service.Source
		}
		kind := recognizeKind(name)
		if kind == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		detected = append(detected, DetectedService{ResourceID: r.ID, Kind: kind, Name: displayResource(r), Source: source, Confidence: recognitionConfidence(name, kind), Endpoints: endpoints[r.ID]})
	}
	sort.Slice(detected, func(i, j int) bool { return detected[i].ResourceID < detected[j].ResourceID })
	inv.DetectedServices = detected
	plan := MonitoringPlan{Version: "infrascout.monitoring/v1", GeneratedAt: inv.CollectedAt, Hostname: inv.Hostname, Recommendations: []MonitoringRecommendation{}, CoverageGaps: []string{}}
	plan.Recommendations = append(plan.Recommendations, MonitoringRecommendation{ID: "monitor.host", TargetID: HostID(inv.Hostname), Collector: "fleetscope/system", Priority: "required", Reason: "collect host CPU, memory, disk, load, and network telemetry with the FleetScope native agent"})
	if hasDocker(inv) {
		plan.Recommendations = append(plan.Recommendations, MonitoringRecommendation{ID: "monitor.docker", TargetID: HostID(inv.Hostname), Collector: "fleetscope/docker", Priority: "required", Reason: "collect container state, resource use, exit codes, and OOM events directly from the Docker Engine API"})
	}
	recommendedServices := map[string]bool{}
	for _, s := range detected {
		serviceName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Name), ".service"))
		key := s.Kind + "\x00" + serviceName
		if recommendedServices[key] {
			continue
		}
		recommendedServices[key] = true
		rec := recommendFor(s)
		plan.Recommendations = append(plan.Recommendations, rec)
	}
	for _, r := range inv.Resources {
		if r.Endpoint != nil && r.Endpoint.ExposedLevel == ExposedPublic {
			matched := false
			for _, s := range detected {
				for _, ep := range s.Endpoints {
					if strings.Contains(ep, fmt.Sprintf(":%d", r.Endpoint.Port)) {
						matched = true
					}
				}
			}
			if !matched {
				plan.CoverageGaps = append(plan.CoverageGaps, fmt.Sprintf("public endpoint %s has no recognized service-specific collector", r.ID))
			}
		}
	}
	sort.Strings(plan.CoverageGaps)
	inv.Monitoring = plan
}

func recognizeKind(v string) string {
	x := strings.ToLower(v)
	for _, pair := range [][2]string{{"nginx", "nginx"}, {"postgres", "postgresql"}, {"postmaster", "postgresql"}, {"mysqld", "mysql"}, {"mariadb", "mysql"}, {"redis-server", "redis"}, {"redis:", "redis"}, {"php-fpm", "php-fpm"}, {"java", "java"}, {"node ", "nodejs"}, {"python", "python"}} {
		if strings.Contains(x, pair[0]) {
			return pair[1]
		}
	}
	return ""
}
func recognitionConfidence(v, kind string) float64 {
	x := strings.ToLower(v)
	if strings.Contains(x, "/"+kind) || strings.Contains(x, kind+":") {
		return .95
	}
	return .8
}
func displayResource(r Resource) string {
	if r.Service != nil {
		return r.Service.Name
	}
	if r.Process != nil {
		return r.Process.Name
	}
	return r.ID
}
func hasDocker(inv *Inventory) bool {
	for _, r := range inv.Resources {
		if r.Service != nil && r.Service.Source == "docker" {
			return true
		}
	}
	return false
}
func recommendFor(s DetectedService) MonitoringRecommendation {
	collector, reason, priority := "fleetscope/process", "collect process availability and resource use with the native agent", "recommended"
	params := map[string]string{}
	switch s.Kind {
	case "nginx":
		collector, reason, priority = "fleetscope/nginx", "collect connections, request rates, and upstream failures from the native Nginx status endpoint", "required"
	case "postgresql":
		collector, reason, priority = "fleetscope/postgresql", "collect connections, transactions, locks, replication, and query health using a read-only database role", "required"
	case "mysql":
		collector, reason, priority = "fleetscope/mysql", "collect connections, replication, InnoDB, and query health using a read-only database role", "required"
	case "redis":
		collector, reason, priority = "fleetscope/redis", "collect memory, clients, persistence, and replication through the Redis protocol", "required"
	case "java":
		collector, reason = "fleetscope/process", "collect JVM process availability, CPU, memory, and thread health with the native agent"
	}
	if len(s.Endpoints) > 0 {
		params["endpoints"] = strings.Join(s.Endpoints, ",")
	}
	return MonitoringRecommendation{ID: "monitor." + sanitizeID(s.ResourceID), TargetID: s.ResourceID, Collector: collector, Priority: priority, Reason: reason, Parameters: params}
}
func sanitizeID(v string) string {
	r := strings.NewReplacer(":", "_", "/", "_", ".", "_")
	return r.Replace(v)
}
