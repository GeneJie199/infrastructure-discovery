package process_test

import (
	"path/filepath"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/process"
)

func TestParseFromRoot_Fixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "host-sample")
	procs, err := process.ParseFromRoot(root)
	if err != nil {
		t.Fatalf("ParseFromRoot: %v", err)
	}
	if len(procs) < 2 {
		t.Fatalf("expected >=2 processes, got %d", len(procs))
	}

	byPID := map[int]process.Info{}
	for _, p := range procs {
		byPID[p.PID] = p
	}

	nginx, ok := byPID[1200]
	if !ok {
		t.Fatal("missing pid 1200")
	}
	if nginx.User != "nginx" {
		t.Fatalf("user=%q", nginx.User)
	}
	if nginx.Exe != "/usr/sbin/nginx" {
		t.Fatalf("exe=%q", nginx.Exe)
	}
	if nginx.Cwd != "/var/www" {
		t.Fatalf("cwd=%q", nginx.Cwd)
	}
	if nginx.Cmdline == "" || nginx.Comm != "nginx" {
		t.Fatalf("cmdline/comm=%q/%q", nginx.Cmdline, nginx.Comm)
	}
	if nginx.StartedAt.IsZero() {
		t.Fatal("startedAt empty")
	}

	sshd, ok := byPID[800]
	if !ok {
		t.Fatal("missing pid 800")
	}
	if sshd.User != "root" {
		t.Fatalf("sshd user=%q", sshd.User)
	}
}
