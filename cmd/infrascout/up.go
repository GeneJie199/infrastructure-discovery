package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
	"github.com/GeneJie199/infrastructure-discovery/internal/web"
	"github.com/spf13/cobra"
)

func upCmd() *cobra.Command {
	var addr, stateDir, fixture, databaseEngine, databaseDSNEnv string
	var noOpen bool
	var databaseTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Scan, initialize drift state, and open the local viewer",
		Long:  "One-command first run: discover this host, create an approved baseline when needed, refresh current drift, and start the local InfraScout UI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			baselinePath := filepath.Join(stateDir, "baseline.json")
			if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
				res, discoverErr := runDiscover(fixture)
				if discoverErr != nil {
					return discoverErr
				}
				if err = initializeState(stateDir, res); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "first scan complete; approved baseline created in %s\n", stateDir)
			} else if err != nil {
				return err
			} else {
				if _, _, err = refreshState(stateDir, fixture); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "current facts and drift refreshed")
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
				diff, baselineCreated, stateErr := updateManagedDatabaseState(stateDir, metadata, false)
				if stateErr != nil {
					return stateErr
				}
				fmt.Fprintf(cmd.OutOrStdout(), "database facts refreshed: engine=%s risk=%s changes=%d baseline_created=%t\n", metadata.Engine, diff.HighestRisk, len(diff.Added)+len(diff.Removed)+len(diff.Changed), baselineCreated)
			}
			url := "http://" + addr + "/"
			if !noOpen {
				go func() {
					time.Sleep(400 * time.Millisecond)
					_ = openBrowser(url)
				}()
			}
			return web.Serve(web.Config{Addr: addr, StateDir: stateDir}, func(format string, values ...any) {
				fmt.Fprintf(cmd.OutOrStdout(), format+"\n", values...)
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8765", "local viewer listen address")
	cmd.Flags().StringVar(&stateDir, "state-dir", ".infrascout", "managed baseline, current facts, decisions, and drift")
	cmd.Flags().StringVar(&fixture, "fixture", "", "fixture root for tests / non-Linux")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not open the viewer in the default browser")
	cmd.Flags().StringVar(&databaseEngine, "database-engine", "", "also collect postgres or mysql read-only metadata")
	cmd.Flags().StringVar(&databaseDSNEnv, "database-dsn-env", "INFRASCOUT_DATABASE_DSN", "environment variable containing the optional database DSN")
	cmd.Flags().DurationVar(&databaseTimeout, "database-timeout", 30*time.Second, "read-only database metadata query timeout")
	return cmd
}

func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	return command.Start()
}
