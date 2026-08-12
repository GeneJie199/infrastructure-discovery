package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
	"github.com/spf13/cobra"
)

func baselineCmd() *cobra.Command {
	var stateDir, fixture string
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Scan the host and save the approved baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := runDiscover(fixture)
			if err != nil {
				return err
			}
			if err := writeState(stateDir, "baseline.json", res.Snapshot); err != nil {
				return err
			}
			if err := writeState(stateDir, "inventory.json", res.Inventory); err != nil {
				return err
			}
			if err := writeYAML(filepath.Join(stateDir, "monitoring-plan.yaml"), res.Inventory.Monitoring); err != nil {
				return err
			}
			if err := writeState(stateDir, "decisions.json", infrascout.DecisionSet{Version: infrascout.DecisionSetVersion, UpdatedAt: infrascout.FormatTime(time.Now()), Decisions: []infrascout.DriftDecision{}}); err != nil {
				return err
			}
			infrascout.FormatScanSummary(cmd.OutOrStdout(), res.Inventory, "baseline")
			fmt.Fprintf(cmd.OutOrStdout(), "approved baseline: %s\n", filepath.Join(stateDir, "baseline.json"))
			printWarnings(cmd, res.Inventory.Warnings)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory for baseline and check results")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	return cmd
}

func checkCmd() *cobra.Command {
	var stateDir, fixture, failOn string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Scan now, compare with the baseline, and write a drift report",
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := parseThreshold(failOn)
			if err != nil {
				return err
			}
			res, report, err := refreshState(stateDir, fixture)
			if err != nil {
				return err
			}
			infrascout.FormatHuman(cmd.OutOrStdout(), report)
			fmt.Fprintf(cmd.OutOrStdout(), "state written to %s\n", stateDir)
			printWarnings(cmd, res.Inventory.Warnings)
			if threshold > 0 && severityRank(report.BlockingRisk) >= threshold && hasChanges(report) {
				return fmt.Errorf("drift reached --fail-on %s threshold", strings.ToLower(failOn))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory containing baseline.json")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "exit non-zero on critical, warning, info, or never")
	return cmd
}

func refreshState(stateDir, fixture string) (*infrascout.ScanResult, infrascout.DiffReport, error) {
	baselinePath := filepath.Join(stateDir, "baseline.json")
	baseline, err := readSnapshot(baselinePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, infrascout.DiffReport{}, fmt.Errorf("baseline not found: run 'infrascout baseline --state-dir %s' first", stateDir)
		}
		return nil, infrascout.DiffReport{}, fmt.Errorf("baseline: %w", err)
	}
	res, err := runDiscover(fixture)
	if err != nil {
		return nil, infrascout.DiffReport{}, err
	}
	report := infrascout.Compare(baseline, res.Snapshot)
	decisions, err := readDecisionSet(stateDir)
	if err != nil {
		return nil, report, fmt.Errorf("decisions: %w", err)
	}
	infrascout.ApplyDecisions(&report, decisions, time.Now())
	if err := writeState(stateDir, "inventory.json", res.Inventory); err != nil {
		return nil, report, err
	}
	if err := writeState(stateDir, "current.json", res.Snapshot); err != nil {
		return nil, report, err
	}
	if err := writeState(stateDir, "drift.json", report); err != nil {
		return nil, report, err
	}
	if err := writeYAML(filepath.Join(stateDir, "monitoring-plan.yaml"), res.Inventory.Monitoring); err != nil {
		return nil, report, err
	}
	return res, report, nil
}

func writeState(dir, name string, value any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, name), value)
}

func parseThreshold(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "never":
		return 0, nil
	case "info":
		return 1, nil
	case "warning":
		return 2, nil
	case "critical":
		return 3, nil
	default:
		return 0, fmt.Errorf("invalid --fail-on %q: use critical, warning, info, or never", value)
	}
}

func severityRank(value infrascout.Severity) int {
	switch value {
	case infrascout.SeverityCritical:
		return 3
	case infrascout.SeverityWarning:
		return 2
	case infrascout.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func hasChanges(report infrascout.DiffReport) bool {
	return len(report.Added)+len(report.Removed)+len(report.Changed) > 0
}

func printWarnings(cmd *cobra.Command, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warning)
	}
}
