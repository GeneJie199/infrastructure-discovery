package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
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
			if err := initializeState(stateDir, res); err != nil {
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

func initializeState(stateDir string, res *infrascout.ScanResult) error {
	approved := res.Snapshot
	approved.State = "approved"
	observed := res.Snapshot
	observed.State = "observed"
	decisions := infrascout.DecisionSet{Version: infrascout.DecisionSetVersion, UpdatedAt: infrascout.FormatTime(time.Now()), Decisions: []infrascout.DriftDecision{}}
	report := infrascout.Compare(approved, observed)
	mergeDatabaseState(stateDir, &report)
	infrascout.ApplyDecisions(&report, decisions, time.Now())
	for name, value := range map[string]any{"baseline.json": approved, "current.json": observed, "inventory.json": res.Inventory, "drift.json": report, "decisions.json": decisions} {
		if err := writeState(stateDir, name, value); err != nil {
			return err
		}
	}
	return writeYAML(filepath.Join(stateDir, "monitoring-plan.yaml"), res.Inventory.Monitoring)
}

func checkCmd() *cobra.Command {
	var stateDir, fixture, failOn, databaseEngine, databaseDSNEnv string
	var databaseTimeout time.Duration
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
			if databaseEngine != "" {
				dsn := os.Getenv(databaseDSNEnv)
				if dsn == "" {
					return fmt.Errorf("environment variable %s is empty", databaseDSNEnv)
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), databaseTimeout)
				metadata, collectErr := dbmeta.Collect(ctx, databaseEngine, dsn)
				cancel()
				if collectErr != nil {
					return collectErr
				}
				if _, _, err = updateManagedDatabaseState(stateDir, metadata, false); err != nil {
					return err
				}
				if report, err = rebuildSavedDrift(stateDir, time.Now()); err != nil {
					return err
				}
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
	cmd.Flags().StringVar(&databaseEngine, "database-engine", "", "also refresh postgres or mysql metadata before evaluating the gate")
	cmd.Flags().StringVar(&databaseDSNEnv, "database-dsn-env", "INFRASCOUT_DATABASE_DSN", "environment variable containing the optional database DSN")
	cmd.Flags().DurationVar(&databaseTimeout, "database-timeout", 30*time.Second, "read-only database metadata query timeout")
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
	mergeDatabaseState(stateDir, &report)
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

func mergeDatabaseState(stateDir string, report *infrascout.DiffReport) {
	var databaseDiff dbmeta.Diff
	if err := readJSONFileInto(filepath.Join(stateDir, "database-diff.json"), &databaseDiff); err == nil {
		dbmeta.MergeIntoInfraReport(report, databaseDiff)
	}
}

func rebuildSavedDrift(stateDir string, now time.Time) (infrascout.DiffReport, error) {
	baseline, err := readSnapshot(filepath.Join(stateDir, "baseline.json"))
	if err != nil {
		return infrascout.DiffReport{}, err
	}
	current, err := readSnapshot(filepath.Join(stateDir, "current.json"))
	if err != nil {
		return infrascout.DiffReport{}, err
	}
	report := infrascout.Compare(baseline, current)
	mergeDatabaseState(stateDir, &report)
	decisions, err := readDecisionSet(stateDir)
	if err != nil {
		return report, err
	}
	infrascout.ApplyDecisions(&report, decisions, now)
	if err = writeState(stateDir, "drift.json", report); err != nil {
		return report, err
	}
	return report, nil
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
