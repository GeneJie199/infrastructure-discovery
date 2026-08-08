package infrascout

import (
	"fmt"
	"io"
	"strings"
)

// FormatHuman writes an operator-friendly drift report.
func FormatHuman(w io.Writer, report DiffReport) {
	fmt.Fprintln(w, "Infrastructure Changes")
	fmt.Fprintln(w, "======================")
	fmt.Fprintf(w, "Compared at: %s\n", report.ComparedAt)
	if report.BaselineTime != "" || report.CandidateTime != "" {
		fmt.Fprintf(w, "Baseline:    %s\n", report.BaselineTime)
		fmt.Fprintf(w, "Candidate:   %s\n", report.CandidateTime)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Added:")
	if len(report.Added) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, a := range report.Added {
			fmt.Fprintf(w, "  + [%s] %s\n", a.Severity, a.Summary)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Removed:")
	if len(report.Removed) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, r := range report.Removed {
			fmt.Fprintf(w, "  - [%s] %s\n", r.Severity, r.Summary)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Changed:")
	if len(report.Changed) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, c := range report.Changed {
			fmt.Fprintf(w, "  ~ [%s] %s\n", c.Severity, c.Summary)
			for k, v := range c.Before {
				fmt.Fprintf(w, "      before.%s = %v\n", k, v)
			}
			for k, v := range c.After {
				fmt.Fprintf(w, "      after.%s  = %v\n", k, v)
			}
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Risk: %s\n", report.HighestRisk)
	for _, a := range report.Added {
		if a.Severity == SeverityCritical {
			fmt.Fprintf(w, "  CRITICAL  %s\n", a.Summary)
		}
	}
	for _, c := range report.Changed {
		if c.Severity == SeverityCritical {
			fmt.Fprintf(w, "  CRITICAL  %s\n", c.Summary)
		}
	}
	if report.HighestRisk == SeverityInfo && len(report.Added)+len(report.Removed)+len(report.Changed) == 0 {
		fmt.Fprintln(w, "  No infrastructure drift detected.")
	}
	fmt.Fprintf(w, "\nUnchanged resources: %d\n", report.Unchanged)
}

// FormatScanSummary prints a short scan summary for humans.
func FormatScanSummary(w io.Writer, inv Inventory, kind string) {
	fmt.Fprintf(w, "InfraScout %s complete\n", kind)
	fmt.Fprintf(w, "  host:       %s\n", inv.Hostname)
	fmt.Fprintf(w, "  collected:  %s\n", inv.CollectedAt)
	fmt.Fprintf(w, "  hosts:      %d\n", inv.Summary.Hosts)
	fmt.Fprintf(w, "  processes:  %d\n", inv.Summary.Processes)
	fmt.Fprintf(w, "  endpoints:  %d\n", inv.Summary.Endpoints)
	fmt.Fprintf(w, "  services:   %d\n", inv.Summary.Services)
	fmt.Fprintf(w, "  relations:  %d\n", len(inv.Relationships))
}

// CriticalLines returns critical messages for scripting.
func CriticalLines(report DiffReport) []string {
	var out []string
	for _, a := range report.Added {
		if a.Severity == SeverityCritical {
			out = append(out, a.Summary)
		}
	}
	for _, c := range report.Changed {
		if c.Severity == SeverityCritical {
			out = append(out, c.Summary)
		}
	}
	return out
}

// JoinCritical is a helper for tests/CLI.
func JoinCritical(report DiffReport) string {
	return strings.Join(CriticalLines(report), "; ")
}
