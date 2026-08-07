//go:build linux

package systemd

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Collect lists systemd service units via systemctl on a live Linux host.
func Collect() ([]Unit, error) {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	units, err := parseListUnits(out)
	if err != nil {
		return nil, err
	}
	// Enrich a subset with systemctl show for active services.
	for i := range units {
		if units[i].ActiveState != "active" && units[i].ActiveState != "activating" {
			continue
		}
		show, err := showUnit(units[i].Name)
		if err != nil {
			continue
		}
		if show.Description != "" {
			units[i].Description = show.Description
		}
		if show.FragmentPath != "" {
			units[i].FragmentPath = show.FragmentPath
		}
		if show.UnitFileState != "" {
			units[i].UnitFileState = show.UnitFileState
		}
		if show.MainPID > 0 {
			units[i].MainPID = show.MainPID
		}
		if show.SubState != "" {
			units[i].SubState = show.SubState
		}
	}
	return units, nil
}

func parseListUnits(out []byte) ([]Unit, error) {
	var units []Unit
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		units = append(units, Unit{
			Name:        name,
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
			Description: desc,
		})
	}
	return units, nil
}

func showUnit(name string) (*Unit, error) {
	cmd := exec.Command(
		"systemctl", "show", name,
		"--property=Description,FragmentPath,UnitFileState,MainPID,SubState,ActiveState,LoadState",
		"--no-pager",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	u := &Unit{Name: name}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Description":
			u.Description = v
		case "FragmentPath":
			u.FragmentPath = v
		case "UnitFileState":
			u.UnitFileState = v
		case "MainPID":
			if n, err := strconv.Atoi(v); err == nil {
				u.MainPID = n
			}
		case "SubState":
			u.SubState = v
		case "ActiveState":
			u.ActiveState = v
		case "LoadState":
			u.LoadState = v
		}
	}
	return u, nil
}
