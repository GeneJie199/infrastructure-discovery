package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
	"github.com/GeneJie199/infrastructure-discovery/internal/web"
	"github.com/spf13/cobra"
)

func watchCmd() *cobra.Command {
	var stateDir, fixture, addr, databaseEngine, databaseDSNEnv string
	var interval, databaseTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously scan, compare with the baseline, and serve the live UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			if interval < 10*time.Second {
				return fmt.Errorf("--interval must be at least 10s")
			}
			refreshDatabase := func() error {
				if databaseEngine == "" {
					return nil
				}
				dsn := os.Getenv(databaseDSNEnv)
				if dsn == "" {
					return fmt.Errorf("environment variable %s is empty", databaseDSNEnv)
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), databaseTimeout)
				defer cancel()
				metadata, err := dbmeta.Collect(ctx, databaseEngine, dsn)
				if err != nil {
					return err
				}
				diff, _, err := updateManagedDatabaseState(stateDir, metadata, false)
				if err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "database scan complete: engine=%s risk=%s changes=%d\n", metadata.Engine, diff.HighestRisk, len(diff.Added)+len(diff.Removed)+len(diff.Changed))
				}
				return err
			}
			refresh := func() {
				res, report, err := refreshState(stateDir, fixture)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "scan failed: %v\n", err)
					return
				}
				fmt.Fprintf(cmd.OutOrStdout(), "scan complete: host=%s risk=%s changes=%d\n",
					res.Inventory.Hostname, report.HighestRisk,
					len(report.Added)+len(report.Removed)+len(report.Changed))
				printWarnings(cmd, res.Inventory.Warnings)
				if err = refreshDatabase(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "database scan failed: %v\n", err)
				}
			}
			if _, _, err := refreshState(stateDir, fixture); err != nil {
				return err
			}
			if err := refreshDatabase(); err != nil {
				return err
			}
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for range ticker.C {
					refresh()
				}
			}()
			return web.Serve(web.Config{
				Addr: addr, InventoryPath: filepath.Join(stateDir, "inventory.json"),
				SnapshotPath: filepath.Join(stateDir, "current.json"),
				DriftPath:    filepath.Join(stateDir, "drift.json"),
				StateDir:     stateDir,
			}, func(format string, args ...any) {
				fmt.Fprintf(cmd.OutOrStdout(), format+"\n", args...)
			})
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "directory containing baseline.json")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8765", "web viewer listen address")
	cmd.Flags().DurationVar(&interval, "interval", time.Minute, "scan interval (minimum 10s)")
	cmd.Flags().StringVar(&databaseEngine, "database-engine", "", "also refresh postgres or mysql metadata on every interval")
	cmd.Flags().StringVar(&databaseDSNEnv, "database-dsn-env", "INFRASCOUT_DATABASE_DSN", "environment variable containing the optional database DSN")
	cmd.Flags().DurationVar(&databaseTimeout, "database-timeout", 30*time.Second, "read-only database metadata query timeout")
	return cmd
}
