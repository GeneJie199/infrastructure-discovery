// Package id builds stable resource IDs and opaque event-style IDs per lifecycle-spec.
package id

import (
	"crypto/rand"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

func newULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

func NewSnapshotID() string   { return "snp_" + newULID() }
func NewInventoryID() string  { return "inv_" + newULID() }
func NewRelationshipID() string { return "rel_" + newULID() }

// Host returns host:{hostname}.
func Host(hostname string) string {
	return "host:" + sanitizeLocator(hostname)
}

// SystemdService returns svc.systemd:{host}/{unit}.
func SystemdService(hostname, unit string) string {
	return fmt.Sprintf("svc.systemd:%s/%s", sanitizeLocator(hostname), sanitizeLocator(unit))
}

// ProcessBin returns process.bin:{host}/{exe}.
// PID must never be part of the ID.
func ProcessBin(hostname, exePath string) string {
	exe := path.Clean(strings.ReplaceAll(exePath, "\\", "/"))
	if exe == "" || exe == "." {
		exe = "unknown"
	}
	return fmt.Sprintf("process.bin:%s/%s", sanitizeLocator(hostname), sanitizePathLocator(exe))
}

// NetListener returns net.listener:{host}/{proto}/{addr}/{port}.
func NetListener(hostname, proto, addr string, port int) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	addr = normalizeAddr(addr)
	return fmt.Sprintf("net.listener:%s/%s/%s/%d", sanitizeLocator(hostname), proto, addr, port)
}

func sanitizeLocator(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "-")
	if s == "" {
		return "unknown"
	}
	return s
}

func sanitizePathLocator(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "unknown"
	}
	return p
}

func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "0.0.0.0" || addr == "*" || addr == "::" {
		return "*"
	}
	// Strip zone index noise (e.g. fe80::1%eth0).
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	return addr
}
