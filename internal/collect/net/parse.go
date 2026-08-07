// Package net collects listening sockets and associates them with processes (INF-003).
package net

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listener is a listening TCP/UDP socket.
type Listener struct {
	Proto      string // tcp, tcp6, udp, udp6
	Addr       string
	Port       int
	Inode      uint64
	PID        int
	ProcessExe string
}

// ParseFromRoot reads {root}/proc/net/{tcp,tcp6,udp,udp6} and maps inodes via
// {root}/proc/<pid>/fd/* content (symlink targets like "socket:[inode]").
func ParseFromRoot(root string) ([]Listener, error) {
	inodeToPID := mapInodes(filepath.Join(root, "proc"))
	pidExe := mapExe(filepath.Join(root, "proc"))

	var out []Listener
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := filepath.Join(root, "proc", "net", proto)
		rows, err := parseSockTable(path, proto)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, r := range rows {
			if !r.Listening {
				continue
			}
			l := Listener{
				Proto: normalizeProto(proto),
				Addr:  r.Addr,
				Port:  r.Port,
				Inode: r.Inode,
			}
			if pid, ok := inodeToPID[r.Inode]; ok {
				l.PID = pid
				l.ProcessExe = pidExe[pid]
			}
			out = append(out, l)
		}
	}
	return out, nil
}

type sockRow struct {
	Addr      string
	Port      int
	Inode     uint64
	Listening bool
}

func parseSockTable(path, proto string) ([]sockRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var rows []sockRow
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		state := fields[3]
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		addr, port, err := parseAddrPort(local, strings.HasSuffix(proto, "6"))
		if err != nil {
			continue
		}
		listening := false
		switch {
		case strings.HasPrefix(proto, "tcp"):
			// 0A = LISTEN
			listening = strings.EqualFold(state, "0A")
		case strings.HasPrefix(proto, "udp"):
			// UDP has no listen state; treat bound ports (non-zero inode) as listeners.
			listening = true
		}
		rows = append(rows, sockRow{
			Addr:      addr,
			Port:      port,
			Inode:     inode,
			Listening: listening,
		})
	}
	return rows, nil
}

func parseAddrPort(local string, v6 bool) (string, int, error) {
	hostHex, portHex, ok := strings.Cut(local, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad local address")
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, err
	}
	addr, err := decodeIP(hostHex, v6)
	if err != nil {
		return "", 0, err
	}
	return addr, int(port64), nil
}

func decodeIP(hostHex string, v6 bool) (string, error) {
	raw, err := hex.DecodeString(hostHex)
	if err != nil {
		return "", err
	}
	if !v6 {
		if len(raw) != 4 {
			return "", fmt.Errorf("bad ipv4")
		}
		// /proc/net/tcp stores little-endian words on little-endian hosts.
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), nil
	}
	if len(raw) != 16 {
		return "", fmt.Errorf("bad ipv6")
	}
	// On Linux, each 32-bit group in /proc/net/tcp6 is little-endian.
	var b [16]byte
	for i := 0; i < 4; i++ {
		chunk := raw[i*4 : i*4+4]
		b[i*4] = chunk[3]
		b[i*4+1] = chunk[2]
		b[i*4+2] = chunk[1]
		b[i*4+3] = chunk[0]
	}
	return net.IP(b[:]).String(), nil
}

func mapInodes(procDir string) map[uint64]int {
	out := map[uint64]int{}
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procDir, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target := readFD(filepath.Join(fdDir, fd.Name()))
			if inode, ok := parseSocketInode(target); ok {
				out[inode] = pid
			}
		}
	}
	return out
}

func mapExe(procDir string) map[int]string {
	out := map[int]string{}
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := filepath.Join(procDir, e.Name(), "exe")
		target, err := os.Readlink(p)
		if err != nil {
			b, err2 := os.ReadFile(p)
			if err2 != nil {
				continue
			}
			target = strings.TrimSpace(string(b))
		}
		out[pid] = target
	}
	return out
}

func readFD(path string) string {
	target, err := os.Readlink(path)
	if err == nil {
		return target
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func parseSocketInode(target string) (uint64, bool) {
	// socket:[12345]
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	n, err := strconv.ParseUint(inner, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func normalizeProto(proto string) string {
	switch proto {
	case "tcp", "tcp6":
		return "tcp"
	case "udp", "udp6":
		return "udp"
	default:
		return proto
	}
}
