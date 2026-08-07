package collect_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect"
	"github.com/GeneJie199/infrastructure-discovery/internal/model"
)

func TestScan_Fixture(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "host-sample")
	res, err := collect.Scan(collect.Options{
		FixtureRoot: root,
		InstanceID:  "infra-discovery-test-01",
		Version:     "0.1.0",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Snapshot.SpecVersion != model.SpecVersion {
		t.Fatalf("specVersion=%s", res.Snapshot.SpecVersion)
	}
	if !strings.HasPrefix(res.Snapshot.SnapshotID, "snp_") {
		t.Fatalf("snapshotId=%s", res.Snapshot.SnapshotID)
	}
	if !contains(res.Snapshot.NoisePolicy.FilteredFields, "attributes.pid") ||
		!contains(res.Snapshot.NoisePolicy.FilteredFields, "attributes.startedAt") {
		t.Fatalf("noisePolicy=%#v", res.Snapshot.NoisePolicy)
	}

	ids := map[string]model.Resource{}
	for _, r := range res.Snapshot.Resources {
		ids[r.ResourceID] = r
	}
	if _, ok := ids["host:shop-prod-api-01"]; !ok {
		t.Fatal("missing host resource")
	}
	if _, ok := ids["svc.systemd:shop-prod-api-01/nginx.service"]; !ok {
		t.Fatal("missing nginx service")
	}
	if _, ok := ids["process.bin:shop-prod-api-01/usr/sbin/nginx"]; !ok {
		t.Fatalf("missing process.bin, ids=%v", keys(ids))
	}
	if _, ok := ids["net.listener:shop-prod-api-01/tcp/*/80"]; !ok {
		t.Fatalf("missing listener, ids=%v", keys(ids))
	}

	// Inventory must strip pid/startedAt.
	for _, r := range res.Inventory.Resources {
		if r.Attributes == nil {
			continue
		}
		if _, ok := r.Attributes["pid"]; ok {
			t.Fatalf("inventory still has pid on %s", r.ResourceID)
		}
		if _, ok := r.Attributes["startedAt"]; ok {
			t.Fatalf("inventory still has startedAt on %s", r.ResourceID)
		}
	}
	if res.Inventory.HostResource != "host:shop-prod-api-01" {
		t.Fatalf("hostResource=%s", res.Inventory.HostResource)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func keys(m map[string]model.Resource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
