package infrascout_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "testdata", name)
	return root
}

func TestDiscoverHostSample(t *testing.T) {
	res, err := infrascout.Discover(infrascout.ScanOptions{FixtureRoot: fixture(t, "host-sample")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inventory.Hostname != "shop-prod-api-01" {
		t.Fatalf("hostname=%s", res.Inventory.Hostname)
	}
	if res.Inventory.Summary.Hosts != 1 {
		t.Fatalf("hosts=%d", res.Inventory.Summary.Hosts)
	}
	if res.Inventory.Summary.Processes < 2 {
		t.Fatalf("processes=%d", res.Inventory.Summary.Processes)
	}
	if res.Inventory.Summary.Endpoints < 2 {
		t.Fatalf("endpoints=%d", res.Inventory.Summary.Endpoints)
	}
	if res.Inventory.Summary.Services < 2 {
		t.Fatalf("services=%d", res.Inventory.Summary.Services)
	}
	if len(res.Inventory.NginxRoutes) != 1 || res.Inventory.NginxRoutes[0].Upstream != "http://127.0.0.1:8080" {
		t.Fatalf("nginx routes=%+v", res.Inventory.NginxRoutes)
	}
	if res.Inventory.Summary.Routes != 1 {
		t.Fatalf("nginx route resources=%d", res.Inventory.Summary.Routes)
	}
	if len(res.Inventory.Monitoring.Recommendations) < 2 {
		t.Fatalf("monitoring plan=%+v", res.Inventory.Monitoring)
	}
	for _, recommendation := range res.Inventory.Monitoring.Recommendations {
		if !strings.HasPrefix(recommendation.Collector, "fleetscope/") {
			t.Fatalf("monitoring plan must use native FleetScope collectors, got %q", recommendation.Collector)
		}
	}

	foundHost, foundRoute := false, false
	for _, r := range res.Snapshot.Resources {
		if strings.Contains(r.ID, "process:") && strings.Contains(r.ID, "1200") {
			t.Fatalf("stable process id must not embed PID: %s", r.ID)
		}
		if r.Type == "host" {
			foundHost = true
			if r.Host == nil || r.Host.Kernel == "" {
				t.Fatal("host kernel missing")
			}
		}
		if r.Type == "nginx.route" {
			foundRoute = true
			if r.Metadata["upstream"] != "http://127.0.0.1:8080" {
				t.Fatalf("route metadata=%+v", r.Metadata)
			}
		}
		if r.Type == "endpoint" && r.Endpoint != nil && r.Endpoint.Port == 80 {
			if r.Endpoint.ProcessName == "" {
				t.Fatal("port 80 should map to process")
			}
			if r.Endpoint.ExposedLevel != infrascout.ExposedPublic {
				t.Fatalf("exposed=%s", r.Endpoint.ExposedLevel)
			}
		}
	}
	if !foundHost {
		t.Fatal("missing host")
	}
	if !foundRoute {
		t.Fatal("missing nginx route in snapshot")
	}
	if len(res.Snapshot.Relationships) == 0 {
		t.Fatal("expected relationships")
	}
}

func TestDiffFixtureMutation(t *testing.T) {
	// Integration-style: scan environment A, mutate to B (new process+port, service change), verify diff.
	oldRes, err := infrascout.Discover(infrascout.ScanOptions{FixtureRoot: fixture(t, "host-sample")})
	if err != nil {
		t.Fatal(err)
	}
	newRes, err := infrascout.Discover(infrascout.ScanOptions{FixtureRoot: fixture(t, "host-sample-v2")})
	if err != nil {
		t.Fatal(err)
	}

	report := infrascout.Compare(oldRes.Snapshot, newRes.Snapshot)

	addedPorts := false
	addedService := false
	removedCron := false
	changedNginx := false
	criticalPublic := false

	for _, a := range report.Added {
		if a.Type == "endpoint" && strings.Contains(a.Summary, "8080") {
			addedPorts = true
			if a.Severity == infrascout.SeverityCritical {
				criticalPublic = true
			}
		}
		if a.Type == "service" && strings.Contains(a.Summary, "mall-api") {
			addedService = true
		}
		if a.Type == "process" && strings.Contains(strings.ToLower(a.Summary), "mall-api") {
			// ok
		}
	}
	for _, r := range report.Removed {
		if r.Type == "service" && strings.Contains(r.Summary, "cron") {
			removedCron = true
			if r.Severity != infrascout.SeverityWarning {
				t.Fatalf("cron removal severity=%s", r.Severity)
			}
		}
	}
	for _, c := range report.Changed {
		if c.Type == "process" || c.Type == "service" {
			if strings.Contains(c.Summary, "nginx") || strings.Contains(c.ID, "nginx") {
				changedNginx = true
				if c.Severity != infrascout.SeverityWarning && c.Severity != infrascout.SeverityInfo {
					t.Fatalf("nginx change severity=%s", c.Severity)
				}
			}
		}
	}

	if !addedPorts {
		t.Fatalf("expected added public port 8080; report=%+v", report.Added)
	}
	if !criticalPublic {
		t.Fatal("expected CRITICAL for new public listener")
	}
	if !addedService {
		t.Fatalf("expected mall-api service added; %+v", report.Added)
	}
	if !removedCron {
		t.Fatalf("expected cron.service removed; %+v", report.Removed)
	}
	if !changedNginx {
		t.Fatalf("expected nginx executable/exec_start change; %+v", report.Changed)
	}
	if report.HighestRisk != infrascout.SeverityCritical {
		t.Fatalf("highest=%s", report.HighestRisk)
	}
}

func TestProcessIDStableWithoutPID(t *testing.T) {
	a := infrascout.ProcessID("h1", "api", "/opt/api/v1/server", "/opt/api")
	b := infrascout.ProcessID("h1", "api", "/opt/api/v2/server", "/opt/api")
	if a != b {
		t.Fatalf("exe upgrade should keep id: %s vs %s", a, b)
	}
	if strings.Contains(a, "1234") {
		t.Fatal(a)
	}
}

func TestDiffCarriesEvidenceForAddedAndRemovedResources(t *testing.T) {
	added := infrascout.Resource{Type: "endpoint", ID: "endpoint:new", Endpoint: &infrascout.Endpoint{Address: "0.0.0.0", Port: 8080, Protocol: "tcp", ExposedLevel: infrascout.ExposedPublic}}
	removed := infrascout.Resource{Type: "service", ID: "service:old", Service: &infrascout.Service{Name: "old.service", ActiveState: "active"}}
	report := infrascout.Compare(
		infrascout.Snapshot{Resources: []infrascout.Resource{removed}},
		infrascout.Snapshot{Resources: []infrascout.Resource{added}},
	)
	if len(report.Added) != 1 || report.Added[0].After["port"] != 8080 {
		t.Fatalf("added evidence = %+v", report.Added)
	}
	if len(report.Removed) != 1 || report.Removed[0].Before["name"] != "old.service" {
		t.Fatalf("removed evidence = %+v", report.Removed)
	}
}
