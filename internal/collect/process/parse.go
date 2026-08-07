// Package process collects Linux process facts from procfs-style trees (INF-003).
package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Info describes one process. PID and StartedAt are attributes (noise for diff).
type Info struct {
	PID       int
	PPID      int
	UID       int
	User      string
	Comm      string
	Cmdline   string
	Exe       string
	Cwd       string
	StartedAt time.Time
	State     string
}

// ParseFromRoot scans {root}/proc/<pid>/ for process records.
// Optional {root}/passwd maps UIDs to usernames (passwd-like lines).
func ParseFromRoot(root string) ([]Info, error) {
	users := loadPasswd(filepath.Join(root, "passwd"))
	bootTime, err := parseBootTime(filepath.Join(root, "proc", "stat"))
	if err != nil {
		// Fixtures may omit boot time; default to Unix epoch for determinism in tests.
		bootTime = time.Unix(0, 0).UTC()
	}
	hz := parseHZ(filepath.Join(root, "clk_tck"))
	procDir := filepath.Join(root, "proc")
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("proc: %w", err)
	}
	var out []Info
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := filepath.Join(procDir, e.Name())
		info, err := parseOne(base, pid, users, bootTime, hz)
		if err != nil {
			continue
		}
		out = append(out, *info)
	}
	return out, nil
}

func parseOne(base string, pid int, users map[int]string, bootTime time.Time, hz int64) (*Info, error) {
	statRaw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return nil, err
	}
	ppid, state, comm, startTicks, err := parseStat(string(statRaw))
	if err != nil {
		return nil, err
	}
	statusUID, _ := parseStatusUID(filepath.Join(base, "status"))
	cmdline := readCmdline(filepath.Join(base, "cmdline"))
	exe := readLink(filepath.Join(base, "exe"))
	cwd := readLink(filepath.Join(base, "cwd"))
	user := users[statusUID]
	if user == "" {
		user = strconv.Itoa(statusUID)
	}
	started := bootTime.Add(time.Duration(startTicks) * time.Second / time.Duration(hz))
	return &Info{
		PID:       pid,
		PPID:      ppid,
		UID:       statusUID,
		User:      user,
		Comm:      comm,
		Cmdline:   cmdline,
		Exe:       exe,
		Cwd:       cwd,
		StartedAt: started.UTC(),
		State:     state,
	}, nil
}

func parseStat(raw string) (ppid int, state, comm string, startTicks int64, err error) {
	// Format: pid (comm) state ppid ... starttime is field 22 (1-based) after comm.
	l := strings.IndexByte(raw, '(')
	r := strings.LastIndexByte(raw, ')')
	if l < 0 || r < 0 || r <= l {
		return 0, "", "", 0, fmt.Errorf("invalid stat")
	}
	comm = raw[l+1 : r]
	rest := strings.Fields(raw[r+1:])
	if len(rest) < 20 {
		return 0, "", "", 0, fmt.Errorf("stat fields short")
	}
	state = rest[0]
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return 0, "", "", 0, err
	}
	startTicks, err = strconv.ParseInt(rest[19], 10, 64)
	if err != nil {
		return 0, "", "", 0, err
	}
	return ppid, state, comm, startTicks, nil
}

func parseStatusUID(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("uid not found")
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	parts := strings.Split(string(b), "\x00")
	var cleaned []string
	for _, p := range parts {
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return strings.Join(cleaned, " ")
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		// Fixtures may store plain files instead of symlinks.
		b, err2 := os.ReadFile(path)
		if err2 != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return target
}

func loadPasswd(path string) map[int]string {
	out := map[int]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		out[uid] = parts[0]
	}
	return out
}

func parseBootTime(statPath string) (time.Time, error) {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				sec, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return time.Time{}, err
				}
				return time.Unix(sec, 0).UTC(), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("btime not found")
}

func parseHZ(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 100
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v <= 0 {
		return 100
	}
	return v
}
