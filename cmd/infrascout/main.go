package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func main() {
	root := &cobra.Command{
		Use:   "infrascout",
		Short: "InfraScout — Linux infrastructure discovery and drift detection",
		Long:  "Discover hosts, processes, listening ports, systemd services, and Docker containers. Build approved baselines, gate releases, and inspect drift locally without AI or remote control.",
	}
	root.AddCommand(scanCmd(), snapshotCmd(), baselineCmd(), checkCmd(), reviewCmd(), promoteCmd(), watchCmd(), diffCmd(), reportCmd(), databaseCmd(), databaseDiffCmd(), serveCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var outPath, fixture, outDir, monitoringPath string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover resources and write inventory.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := runDiscover(fixture)
			if err != nil {
				return err
			}
			path, err := resolveOut(outPath, outDir, "inventory.json")
			if err != nil {
				return err
			}
			if err := writeJSON(path, res.Inventory); err != nil {
				return err
			}
			if monitoringPath != "" {
				if err := writeYAML(monitoringPath, res.Inventory.Monitoring); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", monitoringPath)
			}
			infrascout.FormatScanSummary(cmd.OutOrStdout(), res.Inventory, "scan")
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			printWarnings(cmd, res.Inventory.Warnings)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "inventory.json", "output file path")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory (writes inventory.json inside)")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	cmd.Flags().StringVar(&monitoringPath, "monitoring-plan", "monitoring-plan.yaml", "monitoring recommendation YAML (empty disables)")
	return cmd
}

func writeYAML(path string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".infrascout-yaml-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o644); err == nil {
		_, err = tmp.Write(b)
	}
	if x := tmp.Close(); err == nil {
		err = x
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		if x := os.Remove(path); x != nil && !errors.Is(x, os.ErrNotExist) {
			return err
		}
		return os.Rename(name, path)
	}
	return nil
}

func snapshotCmd() *cobra.Command {
	var outPath, fixture, outDir string
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Discover resources and write snapshot.json for later diff",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := runDiscover(fixture)
			if err != nil {
				return err
			}
			path, err := resolveOut(outPath, outDir, "snapshot.json")
			if err != nil {
				return err
			}
			if err := writeJSON(path, res.Snapshot); err != nil {
				return err
			}
			// Reuse inventory summary fields from same discovery.
			inv := res.Inventory
			infrascout.FormatScanSummary(cmd.OutOrStdout(), inv, "snapshot")
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			printWarnings(cmd, res.Inventory.Warnings)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "snapshot.json", "output file path")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory (writes snapshot.json inside)")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	return cmd
}

func diffCmd() *cobra.Command {
	var jsonOut string
	var quiet bool
	cmd := &cobra.Command{
		Use:   "diff <old-snapshot.json> <new-snapshot.json>",
		Short: "Compare two snapshots and print human-readable drift (and optional JSON)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldSnap, err := readSnapshot(args[0])
			if err != nil {
				return fmt.Errorf("old snapshot: %w", err)
			}
			newSnap, err := readSnapshot(args[1])
			if err != nil {
				return fmt.Errorf("new snapshot: %w", err)
			}
			report := infrascout.Compare(oldSnap, newSnap)
			if !quiet {
				infrascout.FormatHuman(cmd.OutOrStdout(), report)
			}
			if jsonOut != "" {
				if err := writeJSON(jsonOut, report); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "\nwrote JSON report %s\n", jsonOut)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&jsonOut, "json", "j", "", "also write DiffReport JSON to this path")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress human-readable output (use with --json)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), infrascout.Version)
		},
	}
}

func runDiscover(fixture string) (*infrascout.ScanResult, error) {
	res, err := infrascout.Discover(infrascout.ScanOptions{FixtureRoot: fixture})
	if err != nil {
		if errors.Is(err, infrascout.ErrUnsupported) {
			return nil, fmt.Errorf("%w (use --fixture testdata/host-sample on non-Linux)", err)
		}
		return nil, err
	}
	return res, nil
}

func resolveOut(fileFlag, dirFlag, defaultName string) (string, error) {
	if dirFlag != "" {
		if err := os.MkdirAll(dirFlag, 0o755); err != nil {
			return "", err
		}
		return filepath.Join(dirFlag, defaultName), nil
	}
	if fileFlag == "" {
		fileFlag = defaultName
	}
	dir := filepath.Dir(fileFlag)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	return fileFlag, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".infrascout-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Windows cannot always replace an existing destination with Rename.
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(tmpPath, path)
	}
	return nil
}

func readSnapshot(path string) (infrascout.Snapshot, error) {
	var s infrascout.Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, nil
}
