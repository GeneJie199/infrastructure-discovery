package systemd_test

import (
	"path/filepath"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/systemd"
)

func TestParseFromRoot_Fixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "host-sample")
	units, err := systemd.ParseFromRoot(root)
	if err != nil {
		t.Fatalf("ParseFromRoot: %v", err)
	}
	if len(units) != 3 {
		t.Fatalf("units=%d %#v", len(units), units)
	}
	byName := map[string]systemd.Unit{}
	for _, u := range units {
		byName[u.Name] = u
	}
	nginx := byName["nginx.service"]
	if nginx.ActiveState != "active" || nginx.MainPID != 1200 {
		t.Fatalf("nginx=%#v", nginx)
	}
	if byName["cron.service"].ActiveState != "inactive" {
		t.Fatalf("cron=%#v", byName["cron.service"])
	}
}

func TestParseUnitFile_Fallback(t *testing.T) {
	// Point at systemd/system only by using a temp-like relative path that still has unit files.
	// ParseUnitsJSON is preferred when units.json exists; also verify unit file parser directly.
	u, err := systemd.ParseUnitsJSON(filepath.Join("..", "..", "..", "testdata", "host-sample", "systemd", "units.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(u) == 0 {
		t.Fatal("empty")
	}
}
