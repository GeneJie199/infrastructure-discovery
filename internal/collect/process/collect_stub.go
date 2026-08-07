//go:build !linux

package process

import "github.com/GeneJie199/infrastructure-discovery/internal/errs"

// Collect is unavailable on non-Linux platforms.
func Collect() ([]Info, error) {
	return nil, errs.ErrUnsupported
}
