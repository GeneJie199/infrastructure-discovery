//go:build !linux

package host

import "github.com/GeneJie199/infrastructure-discovery/internal/errs"

// Collect is unavailable on non-Linux platforms.
func Collect() (*Info, error) {
	return nil, errs.ErrUnsupported
}
