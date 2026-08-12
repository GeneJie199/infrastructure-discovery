// Package redact removes common secret-bearing command-line values before
// inventory data is written to disk or shown in the web UI.
package redact

import "regexp"

const replacement = "[REDACTED]"

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(--?(?:password|passwd|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret)(?:=|\s+))([^\s]+)`),
	regexp.MustCompile(`(?i)((?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)=)([^\s]+)`),
	regexp.MustCompile(`(?i)(://[^\s:/@]+:)([^\s@]+)(@)`),
}

// CommandLine redacts sensitive values while preserving enough structure for
// operators to identify the executable and non-secret arguments.
func CommandLine(value string) string {
	for _, pattern := range patterns {
		value = pattern.ReplaceAllString(value, `${1}`+replacement+`${3}`)
	}
	return value
}
