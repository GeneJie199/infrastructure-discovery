//go:build linux

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Collect reads live /proc process table.
func Collect() ([]Info, error) {
	return ParseFromRoot("/")
}

// CollectWithPasswd is like Collect but useful when testing passwd overlay is not needed.
func CollectPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join("/proc", e.Name(), "stat")); err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no processes found")
	}
	return pids, nil
}
