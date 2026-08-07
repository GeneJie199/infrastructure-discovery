// Package host collects Linux host basics (INF-002).
package host

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Info is parsed host inventory data.
type Info struct {
	Hostname    string
	OSName      string
	OSVersion   string
	OSID        string
	Kernel      string
	Arch        string
	CPUModel    string
	CPUCores    int
	MemoryBytes int64
	Disks       []Disk
	NICs        []NIC
}

type Disk struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"sizeBytes"`
	MountPoint string `json:"mountPoint,omitempty"`
	FSType     string `json:"fsType,omitempty"`
}

type NIC struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	State     string   `json:"state,omitempty"`
}

// ParseFromRoot reads host facts from a fixture or live root.
// Expected layout (fixture or mapped):
//
//	{root}/hostname
//	{root}/os-release
//	{root}/proc/version
//	{root}/proc/cpuinfo
//	{root}/proc/meminfo
//	{root}/proc/partitions
//	{root}/proc/mounts
//	{root}/proc/net/dev
//	{root}/sys/class/net/<iface>/address  (optional)
//	{root}/sys/class/net/<iface>/operstate (optional)
//	{root}/arch  (optional override; else from cpuinfo flags / uname stub)
func ParseFromRoot(root string) (*Info, error) {
	info := &Info{}

	hn, err := readTrimmed(filepath.Join(root, "hostname"))
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}
	info.Hostname = hn

	if err := parseOSRelease(filepath.Join(root, "os-release"), info); err != nil {
		return nil, err
	}

	ver, err := readTrimmed(filepath.Join(root, "proc", "version"))
	if err != nil {
		return nil, fmt.Errorf("proc/version: %w", err)
	}
	info.Kernel = extractKernel(ver)

	if arch, err := readTrimmed(filepath.Join(root, "arch")); err == nil && arch != "" {
		info.Arch = arch
	}

	if err := parseCPUInfo(filepath.Join(root, "proc", "cpuinfo"), info); err != nil {
		return nil, err
	}
	if err := parseMemInfo(filepath.Join(root, "proc", "meminfo"), info); err != nil {
		return nil, err
	}
	disks, err := parsePartitions(filepath.Join(root, "proc", "partitions"))
	if err != nil {
		return nil, err
	}
	mounts, _ := parseMounts(filepath.Join(root, "proc", "mounts"))
	info.Disks = enrichDisks(disks, mounts)

	nics, err := parseNetDev(filepath.Join(root, "proc", "net", "dev"), root)
	if err != nil {
		return nil, err
	}
	info.NICs = nics

	if info.Arch == "" {
		info.Arch = "unknown"
	}
	return info, nil
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func parseOSRelease(path string, info *Info) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("os-release: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "NAME":
			info.OSName = v
		case "VERSION_ID":
			info.OSVersion = v
		case "ID":
			info.OSID = v
		}
	}
	return sc.Err()
}

func extractKernel(versionLine string) string {
	// Linux version 6.8.0-40-generic (build@...) ...
	parts := strings.Fields(versionLine)
	for i, p := range parts {
		if p == "version" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	if len(parts) >= 3 {
		return parts[2]
	}
	return versionLine
}

func parseCPUInfo(path string, info *Info) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cpuinfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	cores := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "processor") {
			cores++
		}
		if strings.HasPrefix(line, "model name") {
			_, v, ok := strings.Cut(line, ":")
			if ok && info.CPUModel == "" {
				info.CPUModel = strings.TrimSpace(v)
			}
		}
		if info.Arch == "" && strings.HasPrefix(line, "flags") {
			if strings.Contains(line, " lm ") || strings.HasSuffix(line, " lm") {
				info.Arch = "x86_64"
			}
		}
	}
	info.CPUCores = cores
	return sc.Err()
}

func parseMemInfo(path string, info *Info) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("meminfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return err
				}
				info.MemoryBytes = kb * 1024
			}
			break
		}
	}
	return sc.Err()
}

func parsePartitions(path string) ([]Disk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("partitions: %w", err)
	}
	defer f.Close()
	var disks []Disk
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "major") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		blocks, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		name := fields[3]
		// Prefer whole disks (skip partition names ending with digits after letter pattern like sda1).
		if isPartitionName(name) {
			continue
		}
		disks = append(disks, Disk{
			Name:      name,
			SizeBytes: blocks * 1024,
		})
	}
	return disks, sc.Err()
}

func isPartitionName(name string) bool {
	if len(name) < 2 {
		return false
	}
	// nvme0n1p1, sda1, vda2
	last := name[len(name)-1]
	if last < '0' || last > '9' {
		return false
	}
	if strings.Contains(name, "nvme") {
		return strings.Contains(name, "p")
	}
	return true
}

type mountInfo struct {
	device, mount, fsType string
}

func parseMounts(path string) ([]mountInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []mountInfo
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		out = append(out, mountInfo{device: fields[0], mount: fields[1], fsType: fields[2]})
	}
	return out, sc.Err()
}

func enrichDisks(disks []Disk, mounts []mountInfo) []Disk {
	for i := range disks {
		dev := "/dev/" + disks[i].Name
		for _, m := range mounts {
			if m.device == dev || strings.HasPrefix(filepath.Base(m.device), disks[i].Name) {
				if disks[i].MountPoint == "" {
					disks[i].MountPoint = m.mount
					disks[i].FSType = m.fsType
				}
			}
		}
	}
	return disks
}

func parseNetDev(path, root string) ([]NIC, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("net/dev: %w", err)
	}
	defer f.Close()
	var nics []NIC
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		nic := NIC{Name: name}
		addrPath := filepath.Join(root, "sys", "class", "net", name, "address")
		if mac, err := readTrimmed(addrPath); err == nil {
			nic.MAC = mac
		}
		statePath := filepath.Join(root, "sys", "class", "net", name, "operstate")
		if st, err := readTrimmed(statePath); err == nil {
			nic.State = st
		}
		addrsPath := filepath.Join(root, "sys", "class", "net", name, "addresses")
		if raw, err := readTrimmed(addrsPath); err == nil && raw != "" {
			nic.Addresses = splitNonEmpty(raw)
		}
		nics = append(nics, nic)
	}
	return nics, sc.Err()
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n'
	}) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
