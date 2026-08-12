package redact

import (
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	tests := []struct {
		input  string
		secret string
	}{
		{"app --token abc123 --port 80", "abc123"},
		{"app --password=hunter2", "hunter2"},
		{"API_KEY=sk-live-value app", "sk-live-value"},
		{"postgres://alice:secret@db.local/app", "secret"},
	}
	for _, tc := range tests {
		got := CommandLine(tc.input)
		if strings.Contains(got, tc.secret) || !strings.Contains(got, replacement) {
			t.Fatalf("CommandLine(%q) = %q", tc.input, got)
		}
	}
}
