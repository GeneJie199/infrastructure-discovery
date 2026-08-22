package main

import (
	"fmt"

	"github.com/GeneJie199/infrastructure-discovery/internal/web"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var addr, inventoryPath, snapshotPath, driftPath, databasePath, databaseDiffPath, stateDir string
	var demo, allowRemote bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a local web viewer for inventory/snapshot/drift JSON (no external deps)",
		Long: "Serve an embedded, local-first web UI that renders inventory.json, snapshot.json " +
			"and a drift DiffReport. No Node, no CDN — static assets are compiled into the binary.",
		Example: "  infrascout serve --demo\n" +
			"  infrascout serve --inventory inventory.json --drift drift.json\n" +
			"  infrascout serve --addr 127.0.0.1:9000 --snapshot snapshot.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			return web.Serve(web.Config{
				Addr:             addr,
				InventoryPath:    inventoryPath,
				SnapshotPath:     snapshotPath,
				DriftPath:        driftPath,
				DatabasePath:     databasePath,
				DatabaseDiffPath: databaseDiffPath,
				StateDir:         stateDir,
				Demo:             demo,
				AllowRemote:      allowRemote,
			}, func(format string, args ...any) {
				fmt.Fprintf(cmd.OutOrStdout(), format+"\n", args...)
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8765", "listen address")
	cmd.Flags().StringVar(&inventoryPath, "inventory", "", "path to inventory.json from 'infrascout scan'")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "path to snapshot.json from 'infrascout snapshot'")
	cmd.Flags().StringVar(&driftPath, "drift", "", "path to drift DiffReport JSON from 'infrascout diff -j'")
	cmd.Flags().StringVar(&databasePath, "database", "", "path to database metadata JSON from 'infrascout database'")
	cmd.Flags().StringVar(&databaseDiffPath, "database-diff", "", "path to database drift JSON from 'infrascout database-diff'")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "managed state directory; enables review and selective baseline promotion")
	cmd.Flags().BoolVar(&demo, "demo", false, "load embedded fixture demo instead of files")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow non-loopback read-only viewing; review and promotion APIs stay disabled")
	return cmd
}
