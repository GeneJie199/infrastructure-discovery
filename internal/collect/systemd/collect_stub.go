//go:build !linux

package systemd

import "github.com/GeneJie199/infrastructure-discovery/internal/errs"

// Collect is unavailable on non-Linux platforms.
func Collect() ([]Unit, error) {
	return nil, errs.ErrUnsupported
}
