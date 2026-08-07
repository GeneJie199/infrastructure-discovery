//go:build !linux

package net

import "github.com/GeneJie199/infrastructure-discovery/internal/errs"

// Collect is unavailable on non-Linux platforms.
func Collect() ([]Listener, error) {
	return nil, errs.ErrUnsupported
}
