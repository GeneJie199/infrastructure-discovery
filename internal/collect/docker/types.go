// Package docker discovers running Docker containers through the local CLI.
package docker

type Container struct {
	ID            string
	Name          string
	Image         string
	Command       string
	State         string
	Status        string
	Ports         string
	Labels        string
	Health        string
	RestartCount  int
	RestartPolicy string
	Networks      []string
	Mounts        []Mount
}

type Mount struct{ Type, Source, Destination, Mode string }
