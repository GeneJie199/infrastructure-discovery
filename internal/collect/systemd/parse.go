// Package systemd identifies systemd units (INF-004).
package systemd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Unit is a systemd service (or other unit type) observation.
type Unit struct {
	Name        string `json:"name"`
	LoadState   string `json:"loadState"`
	ActiveState string `json:"activeState"`
	SubState    string `json:"subState"`
	Description string `json:"description,omitempty"`
	FragmentPath string `json:"fragmentPath,omitempty"`
	UnitFileState string `json:"unitFileState,omitempty"`
	MainPID     int    `json:"mainPID,omitempty"`
}

// ParseUnitsJSON reads a systemctl show / list-units style JSON fixture:
//
//	{ "units": [ { "name": "nginx.service", "activeState": "active", ... } ] }
func ParseUnitsJSON(path string) ([]Unit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Units []Unit `json:"units"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("systemd units json: %w", err)
	}
	return payload.Units, nil
}

// ParseUnitFiles reads simple drop-in style unit files under {root}/systemd/system/*.service
// and merges optional state from {root}/systemd/units.json when present.
func ParseFromRoot(root string) ([]Unit, error) {
	jsonPath := filepath.Join(root, "systemd", "units.json")
	if _, err := os.Stat(jsonPath); err == nil {
		return ParseUnitsJSON(jsonPath)
	}

	dir := filepath.Join(root, "systemd", "system")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("systemd/system: %w", err)
	}
	var units []Unit
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
			continue
		}
		u, err := parseUnitFile(filepath.Join(dir, e.Name()), e.Name())
		if err != nil {
			continue
		}
		units = append(units, *u)
	}
	return units, nil
}

func parseUnitFile(path, name string) (*Unit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	u := &Unit{
		Name:          name,
		LoadState:     "loaded",
		ActiveState:   "unknown",
		SubState:      "unknown",
		FragmentPath:  path,
		UnitFileState: "enabled",
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Description":
			u.Description = v
		case "ActiveState":
			u.ActiveState = v
		case "SubState":
			u.SubState = v
		case "UnitFileState":
			u.UnitFileState = v
		}
	}
	return u, nil
}
