package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect"
	"github.com/GeneJie199/infrastructure-discovery/internal/diff"
	"github.com/GeneJie199/infrastructure-discovery/internal/model"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "infra-discovery",
		Short: "Linux infrastructure discovery (inventory + snapshot + drift)",
		Long:  "Discover Linux host, process, listener, and systemd resources. Outputs lifecycle-spec aligned inventory.json and snapshot.json.",
	}
	root.AddCommand(scanCmd(), diffCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var outDir string
	var fixture string
	var instanceID string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan host and write inventory.json + snapshot.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				return errors.New("--out is required")
			}
			res, err := collect.Scan(collect.Options{
				FixtureRoot: fixture,
				InstanceID:  instanceID,
				Version:     version,
			})
			if err != nil {
				if errors.Is(err, collect.ErrUnsupported) {
					return fmt.Errorf("%w (on Windows/macOS use --fixture testdata/host-sample)", err)
				}
				return err
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if err := writeJSON(filepath.Join(outDir, "inventory.json"), res.Inventory); err != nil {
				return err
			}
			if err := writeJSON(filepath.Join(outDir, "snapshot.json"), res.Snapshot); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.Join(outDir, "inventory.json"))
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.Join(outDir, "snapshot.json"))
			fmt.Fprintf(cmd.OutOrStdout(), "resources=%d relationships=%d host=%s\n",
				len(res.Snapshot.Resources), len(res.Snapshot.Relationships), res.Inventory.HostResource)
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "", "output directory")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root (fake /proc + systemd) for tests or non-Linux")
	cmd.Flags().StringVar(&instanceID, "instance-id", "", "source.instanceId (default: infra-discovery-<hostname>)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func diffCmd() *cobra.Command {
	var baselinePath, candidatePath, outPath string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two snapshot.json files and emit drift JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			baseline, err := readSnapshot(baselinePath)
			if err != nil {
				return fmt.Errorf("baseline: %w", err)
			}
			candidate, err := readSnapshot(candidatePath)
			if err != nil {
				return fmt.Errorf("candidate: %w", err)
			}
			report := diff.Compare(baseline, candidate)
			if outPath == "" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if err := writeJSON(outPath, report); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (added=%d removed=%d changed=%d unchanged=%d)\n",
				outPath, len(report.Added), len(report.Removed), len(report.Changed), report.UnchangedCount)
			return nil
		},
	}
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline snapshot.json")
	cmd.Flags().StringVar(&candidatePath, "candidate", "", "candidate snapshot.json")
	cmd.Flags().StringVar(&outPath, "out", "", "optional drift output path (default: stdout)")
	_ = cmd.MarkFlagRequired("baseline")
	_ = cmd.MarkFlagRequired("candidate")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func readSnapshot(path string) (model.Snapshot, error) {
	var s model.Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, nil
}
