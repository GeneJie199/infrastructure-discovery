//go:build linux

package net

// Collect reads live listening sockets from /proc.
func Collect() ([]Listener, error) {
	return ParseFromRoot("/")
}
