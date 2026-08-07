package host_test

import (
	"path/filepath"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/host"
)

func TestParseFromRoot_Fixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "host-sample")
	info, err := host.ParseFromRoot(root)
	if err != nil {
		t.Fatalf("ParseFromRoot: %v", err)
	}
	if info.Hostname != "shop-prod-api-01" {
		t.Fatalf("hostname=%q", info.Hostname)
	}
	if info.OSID != "ubuntu" || info.OSVersion != "24.04" {
		t.Fatalf("os=%s %s", info.OSID, info.OSVersion)
	}
	if info.Kernel != "6.8.0-40-generic" {
		t.Fatalf("kernel=%q", info.Kernel)
	}
	if info.Arch != "x86_64" {
		t.Fatalf("arch=%q", info.Arch)
	}
	if info.CPUCores != 2 {
		t.Fatalf("cpuCores=%d", info.CPUCores)
	}
	if info.MemoryBytes != 7962488*1024 {
		t.Fatalf("memoryBytes=%d", info.MemoryBytes)
	}
	if len(info.Disks) < 2 {
		t.Fatalf("expected disks, got %#v", info.Disks)
	}
	if len(info.NICs) != 2 {
		t.Fatalf("nics=%d", len(info.NICs))
	}
	var eth0 bool
	for _, n := range info.NICs {
		if n.Name == "eth0" && n.MAC == "06:2a:8b:3c:11:22" && n.State == "up" {
			eth0 = true
		}
	}
	if !eth0 {
		t.Fatalf("eth0 not parsed: %#v", info.NICs)
	}
}
