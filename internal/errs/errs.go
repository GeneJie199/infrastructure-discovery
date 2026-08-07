// Package errs holds shared sentinel errors for collectors.
package errs

import "errors"

// ErrUnsupported indicates a live collector cannot run on this platform.
var ErrUnsupported = errors.New("collector unsupported on this platform; use --fixture or run on Linux")
