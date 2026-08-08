package infrascout

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

// Stable IDs never use raw PID as the sole identity.

func HostID(hostname string) string {
	return "host:" + hostname
}

// ProcessID is stable across restarts and binary path upgrades.
// Uses process name (comm) + working directory; executable is a mutable attribute.
// PID is never part of the ID.
func ProcessID(hostname, name, executable, cwd string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = pathBase(executable)
	}
	if name == "" {
		name = "unknown"
	}
	cwd = normalizePath(cwd)
	if cwd != "" {
		sum := sha1.Sum([]byte(cwd))
		return fmt.Sprintf("process:%s/%s@%s", hostname, name, hex.EncodeToString(sum[:6]))
	}
	base := pathBase(executable)
	if base == "" {
		base = name
	}
	return fmt.Sprintf("process:%s/%s/%s", hostname, name, base)
}

func EndpointID(hostname, proto, addr string, port int) string {
	return fmt.Sprintf("endpoint:%s/%s/%s/%d", hostname, strings.ToLower(proto), normalizeAddr(addr), port)
}

func ServiceID(hostname, name string) string {
	return fmt.Sprintf("service:systemd:%s/%s", hostname, name)
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	return strings.TrimPrefix(p, "/")
}

func normalizeAddr(addr string) string {
	switch addr {
	case "0.0.0.0", "::", "*", "":
		return "*"
	case "::1":
		return "127.0.0.1"
	default:
		return addr
	}
}

// ClassifyExposed maps bind address to exposure level.
func ClassifyExposed(addr string) ExposedLevel {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case "0.0.0.0", "::", "*":
		return ExposedPublic
	case "127.0.0.1", "::1", "localhost":
		return ExposedLocalhost
	case "":
		return ExposedUnknown
	default:
		return ExposedPrivate
	}
}
