package configscan

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type NginxRoute struct{ SourceFile, ServerName, Listen, Location, Upstream string }

var directive = regexp.MustCompile(`^\s*(server_name|listen|location|proxy_pass)\s+([^;{]+)`)

func ParseNginx(root string) ([]NginxRoute, []string, error) {
	if root == "" {
		return nil, nil, nil
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	routes := []NginxRoute{}
	warnings := []string{}
	files := []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == "nginx.conf" || strings.HasSuffix(d.Name(), ".conf") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(files)
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		current := NginxRoute{SourceFile: path}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
			m := directive.FindStringSubmatch(line)
			if len(m) != 3 {
				continue
			}
			value := strings.Trim(strings.TrimSpace(m[2]), "'")
			switch m[1] {
			case "server_name":
				current.ServerName = value
			case "listen":
				current.Listen = value
			case "location":
				current.Location = value
			case "proxy_pass":
				if strings.Contains(value, "$") {
					warnings = append(warnings, path+": dynamic proxy_pass omitted")
					continue
				}
				route := current
				route.Upstream = value
				routes = append(routes, route)
			}
		}
		if err = sc.Err(); err != nil {
			warnings = append(warnings, err.Error())
		}
		f.Close()
	}
	return routes, warnings, nil
}
