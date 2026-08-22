package main

import (
	"encoding/json"
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

func reviewCmd() *cobra.Command {
	command := &cobra.Command{Use: "review", Short: "List or classify individual infrastructure changes"}
	command.AddCommand(reviewListCmd(), reviewSetCmd())
	return command
}

func reviewListCmd() *cobra.Command {
	var stateDir string
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "list",
		Short: "List current changes with fingerprints and dispositions",
		RunE: func(command *cobra.Command, _ []string) error {
			report, err := readDriftReport(filepath.Join(stateDir, "drift.json"))
			if err != nil {
				return err
			}
			decisions, err := readDecisionSet(stateDir)
			if err != nil {
				return err
			}
			infrascout.ApplyDecisions(&report, decisions, time.Now())
			if jsonOutput {
				return json.NewEncoder(command.OutOrStdout()).Encode(report)
			}
			printItem := func(kind, id, itemFingerprint string, classification infrascout.DriftClassification, severity infrascout.Severity, summary string, expired bool) {
				suffix := ""
				if expired {
					suffix = " (temporary decision expired)"
				}
				fmt.Fprintf(command.OutOrStdout(), "%s %-10s %-10s %s %s\n  %s%s\n", itemFingerprint, kind, classification, severity, id, summary, suffix)
			}
			for _, item := range report.Added {
				printItem("added", item.ID, item.Fingerprint, item.Classification, item.Severity, item.Summary, item.DecisionExpired)
			}
			for _, item := range report.Removed {
				printItem("removed", item.ID, item.Fingerprint, item.Classification, item.Severity, item.Summary, item.DecisionExpired)
			}
			for _, item := range report.Changed {
				printItem("changed", item.ID, item.Fingerprint, item.Classification, item.Severity, item.Summary, item.DecisionExpired)
			}
			return nil
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory containing drift.json and decisions.json")
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit the enriched drift report as JSON")
	return command
}

func reviewSetCmd() *cobra.Command {
	var stateDir, fingerprint, resourceID, classification, actor, note, expiresAt string
	command := &cobra.Command{
		Use:   "set",
		Short: "Classify one current change with an auditable decision",
		RunE: func(command *cobra.Command, _ []string) error {
			if (fingerprint == "") == (resourceID == "") {
				return errors.New("set exactly one of --fingerprint or --resource")
			}
			now := time.Now().UTC().Truncate(time.Second)
			report, err := readDriftReport(filepath.Join(stateDir, "drift.json"))
			if err != nil {
				return err
			}
			decisions, err := readDecisionSet(stateDir)
			if err != nil {
				return err
			}
			infrascout.ApplyDecisions(&report, decisions, now)
			resolvedFingerprint, resolvedResource, kind, err := infrascout.FindDriftItem(report, fingerprint, resourceID)
			if err != nil {
				return err
			}
			decision := infrascout.DriftDecision{
				Fingerprint: resolvedFingerprint, ResourceID: resolvedResource, ChangeKind: kind,
				Classification: infrascout.DriftClassification(strings.ToLower(classification)), Actor: strings.TrimSpace(actor), Note: strings.TrimSpace(note),
				DecidedAt: infrascout.FormatTime(now), ExpiresAt: strings.TrimSpace(expiresAt),
			}
			if err := decisions.Upsert(decision, now); err != nil {
				return err
			}
			if err := writeState(stateDir, "decisions.json", decisions); err != nil {
				return err
			}
			infrascout.ApplyDecisions(&report, decisions, now)
			if err := writeState(stateDir, "drift.json", report); err != nil {
				return err
			}
			fmt.Fprintf(command.OutOrStdout(), "classified %s as %s by %s\n", resolvedFingerprint, decision.Classification, decision.Actor)
			return nil
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory containing drift.json and decisions.json")
	command.Flags().StringVar(&fingerprint, "fingerprint", "", "exact drift fingerprint")
	command.Flags().StringVar(&resourceID, "resource", "", "resource ID when it identifies exactly one current change")
	command.Flags().StringVar(&classification, "classification", "", "expected, approved, temporary, unexpected, or denied")
	command.Flags().StringVar(&actor, "actor", "", "human or system identity making the decision")
	command.Flags().StringVar(&note, "note", "", "decision rationale")
	command.Flags().StringVar(&expiresAt, "expires", "", "RFC3339 expiry required for temporary decisions")
	_ = command.MarkFlagRequired("classification")
	_ = command.MarkFlagRequired("actor")
	_ = command.MarkFlagRequired("note")
	return command
}

func promoteCmd() *cobra.Command {
	var stateDir, fingerprint, resourceID string
	command := &cobra.Command{
		Use:   "promote",
		Short: "Promote one approved or expected change into the baseline",
		RunE: func(command *cobra.Command, _ []string) error {
			if (fingerprint == "") == (resourceID == "") {
				return errors.New("set exactly one of --fingerprint or --resource")
			}
			now := time.Now().UTC()
			baseline, err := readSnapshot(filepath.Join(stateDir, "baseline.json"))
			if err != nil {
				return err
			}
			current, err := readSnapshot(filepath.Join(stateDir, "current.json"))
			if err != nil {
				return err
			}
			report := infrascout.Compare(baseline, current)
			mergeDatabaseState(stateDir, &report)
			decisions, err := readDecisionSet(stateDir)
			if err != nil {
				return err
			}
			infrascout.ApplyDecisions(&report, decisions, now)
			resolvedFingerprint, resolvedResource, kind, err := infrascout.FindDriftItem(report, fingerprint, resourceID)
			if err != nil {
				return err
			}
			classification := driftClassification(report, resolvedFingerprint)
			if classification != infrascout.ClassificationApproved && classification != infrascout.ClassificationExpected {
				return fmt.Errorf("change is %s; only approved or expected changes can be promoted", classification)
			}
			if strings.HasPrefix(resolvedResource, "dbmeta:") {
				var databaseBaseline, databaseCurrent dbmeta.Metadata
				if err = readJSONFileInto(filepath.Join(stateDir, "database-baseline.json"), &databaseBaseline); err != nil {
					return err
				}
				if err = readJSONFileInto(filepath.Join(stateDir, "database-current.json"), &databaseCurrent); err != nil {
					return err
				}
				if err = dbmeta.PromoteChange(&databaseBaseline, databaseCurrent, resolvedResource, kind); err != nil {
					return err
				}
				if err = writeState(stateDir, "database-baseline.json", databaseBaseline); err != nil {
					return err
				}
				if err = writeState(stateDir, "database-diff.json", dbmeta.Compare(databaseBaseline, databaseCurrent)); err != nil {
					return err
				}
				if report, err = rebuildSavedDrift(stateDir, now); err != nil {
					return err
				}
			} else {
				infrascout.PromoteResource(&baseline, current, resolvedResource, kind)
				baseline.Timestamp = infrascout.FormatTime(now)
				if err := writeState(stateDir, "baseline.json", baseline); err != nil {
					return err
				}
				report = infrascout.Compare(baseline, current)
				mergeDatabaseState(stateDir, &report)
				infrascout.ApplyDecisions(&report, decisions, now)
				if err := writeState(stateDir, "drift.json", report); err != nil {
					return err
				}
			}
			fmt.Fprintf(command.OutOrStdout(), "promoted %s (%s %s) into baseline\n", resolvedFingerprint, kind, resolvedResource)
			return nil
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory containing baseline.json and current.json")
	command.Flags().StringVar(&fingerprint, "fingerprint", "", "exact drift fingerprint")
	command.Flags().StringVar(&resourceID, "resource", "", "resource ID when it identifies exactly one current change")
	return command
}

func readDecisionSet(stateDir string) (infrascout.DecisionSet, error) {
	var set infrascout.DecisionSet
	data, err := os.ReadFile(filepath.Join(stateDir, "decisions.json"))
	if errors.Is(err, os.ErrNotExist) {
		set.Version = infrascout.DecisionSetVersion
		set.Decisions = []infrascout.DriftDecision{}
		return set, nil
	}
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return set, err
	}
	return set, set.Normalize(time.Now())
}

func readDriftReport(path string) (infrascout.DiffReport, error) {
	var report infrascout.DiffReport
	data, err := os.ReadFile(path)
	if err != nil {
		return report, err
	}
	return report, json.Unmarshal(data, &report)
}

func driftClassification(report infrascout.DiffReport, fingerprint string) infrascout.DriftClassification {
	for _, item := range report.Added {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	for _, item := range report.Removed {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	for _, item := range report.Changed {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	return infrascout.ClassificationUnexpected
}
