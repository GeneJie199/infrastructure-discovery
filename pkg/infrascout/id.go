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

func ContainerID(hostname, name string) string {
	return fmt.Sprintf("service:docker:%s/%s", hostname, strings.TrimPrefix(strings.TrimSpace(name), "/"))
}

func DeploymentID(hostname, method, name string) string {
	return fmt.Sprintf("deployment:%s:%s/%s", strings.ToLower(method), hostname, normalizePath(name))
}

func DatabaseID(hostname, engine, resourceID string) string {
	sum := sha1.Sum([]byte(resourceID))
	return fmt.Sprintf("database:%s:%s/%s", strings.ToLower(engine), hostname, hex.EncodeToString(sum[:8]))
}

func DockerNetworkID(hostname, name string) string {
	return fmt.Sprintf("docker.network:%s/%s", hostname, normalizePath(name))
}

// RelationshipID is stable across scans and does not include volatile evidence.
func RelationshipID(r Relationship) string {
	sum := sha1.Sum([]byte(strings.Join([]string{r.Source, r.Type, r.Target}, "\x00")))
	return "relationship:" + hex.EncodeToString(sum[:10])
}
func DockerVolumeID(hostname, source string) string {
	sum := sha1.Sum([]byte(source))
	return fmt.Sprintf("docker.volume:%s/%s", hostname, hex.EncodeToString(sum[:8]))
}

func NginxRouteID(hostname, sourceFile, serverName, listen, location string) string {
	identity := strings.Join([]string{normalizePath(sourceFile), serverName, listen, location}, "\x00")
	sum := sha1.Sum([]byte(identity))
	return fmt.Sprintf("nginx.route:%s/%s", hostname, hex.EncodeToString(sum[:8]))
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
