package infrascout

import (
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/process"
)

func TestExcludeCurrentProcessTree(t *testing.T) {
	input := []process.Info{
		{PID: 1, PPID: 0, Comm: "systemd"},
		{PID: 10, PPID: 1, Comm: "sshd"},
		{PID: 20, PPID: 10, Comm: "bash"},
		{PID: 30, PPID: 20, Comm: "infrascout"},
		{PID: 40, PPID: 1, Comm: "app"},
		{PID: 50, PPID: 2, Comm: "kworker/0:1"},
	}
	got := excludeProcesses(input, currentProcessTreePIDs(input, 30))
	if len(got) != 2 || got[0].PID != 1 || got[1].PID != 40 {
		t.Fatalf("filtered processes = %+v", got)
	}
}
