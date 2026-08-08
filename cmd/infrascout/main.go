package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "infrascout",
		Short: "InfraScout — Linux infrastructure discovery and drift detection",
		Long:  "Discover host, processes, listening ports, and systemd services. Local-first CLI. No AI, Docker, or remote control in v0.1.",
	}
	root.AddCommand(scanCmd(), snapshotCmd(), diffCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var outPath, fixture, outDir string
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
			infrascout.FormatScanSummary(cmd.OutOrStdout(), res.Inventory, "scan")
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "inventory.json", "output file path")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory (writes inventory.json inside)")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	return cmd
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
	return os.WriteFile(path, b, 0o644)
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
