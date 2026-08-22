package docker

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Collect returns running containers. Docker being absent or inaccessible is
// reported as an availability error so callers can degrade gracefully.
func Collect() ([]Container, error) {
	path, err := exec.LookPath("docker")
	if err != nil {
		return nil, errors.New("docker CLI not found")
	}
	cmd := exec.Command(path, "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %s", strings.TrimSpace(string(out)))
	}
	containers, err := Parse(out)
	if err != nil || len(containers) == 0 {
		return containers, err
	}
	args := []string{"inspect"}
	for _, c := range containers {
		args = append(args, c.ID)
	}
	inspect := exec.Command(path, args...)
	details, inspectErr := inspect.CombinedOutput()
	if inspectErr != nil {
		return containers, fmt.Errorf("docker inspect: %s", strings.TrimSpace(string(details)))
	}
	if err = ApplyInspect(containers, details); err != nil {
		return containers, err
	}
	return containers, nil
}

func ApplyInspect(containers []Container, data []byte) error {
	var rows []struct {
		ID           string `json:"Id"`
		RestartCount int    `json:"RestartCount"`
		State        struct {
			Health *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		NetworkSettings struct {
			Networks map[string]any `json:"Networks"`
		} `json:"NetworkSettings"`
		Mounts     []struct{ Type, Source, Destination, Mode string } `json:"Mounts"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return fmt.Errorf("docker inspect output: %w", err)
	}
	idx := map[string]int{}
	for i, c := range containers {
		idx[c.ID] = i
	}
	for _, x := range rows {
		i, ok := idx[x.ID]
		if !ok {
			continue
		}
		containers[i].RestartCount = x.RestartCount
		containers[i].RestartPolicy = x.HostConfig.RestartPolicy.Name
		if x.State.Health != nil {
			containers[i].Health = x.State.Health.Status
		}
		for name := range x.NetworkSettings.Networks {
			containers[i].Networks = append(containers[i].Networks, name)
		}
		sort.Strings(containers[i].Networks)
		for _, m := range x.Mounts {
			containers[i].Mounts = append(containers[i].Mounts, Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, Mode: m.Mode})
		}
		sort.Slice(containers[i].Mounts, func(a, b int) bool { return containers[i].Mounts[a].Destination < containers[i].Mounts[b].Destination })
	}
	return nil
}

// Parse parses one Docker JSON object per line.
func Parse(data []byte) ([]Container, error) {
	var result []Container
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw struct {
			ID      string `json:"ID"`
			Names   string `json:"Names"`
			Image   string `json:"Image"`
			Command string `json:"Command"`
			State   string `json:"State"`
			Status  string `json:"Status"`
			Ports   string `json:"Ports"`
			Labels  string `json:"Labels"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("docker output: %w", err)
		}
		result = append(result, Container{
			ID: raw.ID, Name: raw.Names, Image: raw.Image, Command: raw.Command,
			State: raw.State, Status: raw.Status, Ports: raw.Ports, Labels: raw.Labels,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
