// Package collect orchestrates Linux infrastructure discovery collectors.
package collect

import "github.com/GeneJie199/infrastructure-discovery/internal/model"

// Options configures a scan.
type Options struct {
	// FixtureRoot, when set, reads fake /proc and systemd fixtures from that directory
	// instead of live system paths. Layout:
	//   {root}/proc/...
	//   {root}/hostname
	//   {root}/os-release
	//   {root}/systemd/units.json
	FixtureRoot string
	InstanceID  string
	Version     string
	Context     *model.Context
}

// Result holds inventory + snapshot produced by a scan.
type Result struct {
	Inventory model.Inventory
	Snapshot  model.Snapshot
}
