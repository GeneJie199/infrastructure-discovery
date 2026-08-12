//go:build linux

package host

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Collect gathers live host facts from the running Linux system.
func Collect() (*Info, error) {
	tmp, err := os.MkdirTemp("", "infra-discovery-host-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	if err := materializeLiveRoot(tmp); err != nil {
		return nil, err
	}
	return ParseFromRoot(tmp)
}

func materializeLiveRoot(root string) error {
	copies := map[string]string{
		"/etc/hostname":    "hostname",
		"/etc/os-release":  "os-release",
		"/proc/version":    "proc/version",
		"/proc/cpuinfo":    "proc/cpuinfo",
		"/proc/meminfo":    "proc/meminfo",
		"/proc/partitions": "proc/partitions",
		"/proc/mounts":     "proc/mounts",
		"/proc/net/dev":    "proc/net/dev",
	}
	for src, dst := range copies {
		if err := copyFile(src, filepath.Join(root, dst)); err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
	}
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		_ = os.WriteFile(filepath.Join(root, "arch"), []byte(strings.TrimSpace(string(out))), 0o644)
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == "lo" {
				continue
			}
			base := filepath.Join(root, "sys", "class", "net", name)
			_ = os.MkdirAll(base, 0o755)
			_ = copyFile(filepath.Join("/sys/class/net", name, "address"), filepath.Join(base, "address"))
			_ = copyFile(filepath.Join("/sys/class/net", name, "operstate"), filepath.Join(base, "operstate"))
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}
