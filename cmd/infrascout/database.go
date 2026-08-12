package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
	"github.com/spf13/cobra"
)

func databaseCmd() *cobra.Command {
	var engine, dsnEnv, out string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "database", Short: "Collect read-only PostgreSQL or MySQL structure and privilege metadata", RunE: func(cmd *cobra.Command, args []string) error {
		dsn := os.Getenv(dsnEnv)
		if dsn == "" {
			return fmt.Errorf("environment variable %s is empty", dsnEnv)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()
		m, err := dbmeta.Collect(ctx, engine, dsn)
		if err != nil {
			return err
		}
		if err = writeJSON(out, m); err != nil {
			return err
		}
		tables := 0
		for _, s := range m.Schemas {
			tables += len(s.Tables)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "database metadata: %s, %d schemas, %d tables\nwrote %s\n", m.Engine, len(m.Schemas), tables, out)
		return nil
	}}
	cmd.Flags().StringVar(&engine, "engine", "", "postgres or mysql")
	cmd.Flags().StringVar(&dsnEnv, "dsn-env", "INFRASCOUT_DATABASE_DSN", "environment variable containing DSN")
	cmd.Flags().StringVarP(&out, "output", "o", "database-metadata.json", "output JSON")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "read-only query timeout")
	_ = cmd.MarkFlagRequired("engine")
	return cmd
}

func databaseDiffCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{Use: "database-diff <old-metadata.json> <new-metadata.json>", Short: "Compare two database metadata documents", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		read := func(path string) (dbmeta.Metadata, error) {
			f, err := os.Open(path)
			if err != nil {
				return dbmeta.Metadata{}, err
			}
			defer f.Close()
			var metadata dbmeta.Metadata
			decoder := json.NewDecoder(f)
			decoder.DisallowUnknownFields()
			if err = decoder.Decode(&metadata); err != nil {
				return dbmeta.Metadata{}, err
			}
			if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				if err == nil {
					return dbmeta.Metadata{}, errors.New("metadata must contain one JSON object")
				}
				return dbmeta.Metadata{}, fmt.Errorf("invalid trailing JSON: %w", err)
			}
			if metadata.Version != "infrascout.database/v1" {
				return dbmeta.Metadata{}, fmt.Errorf("unsupported database metadata version %q", metadata.Version)
			}
			return metadata, nil
		}
		before, err := read(args[0])
		if err != nil {
			return fmt.Errorf("old metadata: %w", err)
		}
		after, err := read(args[1])
		if err != nil {
			return fmt.Errorf("new metadata: %w", err)
		}
		if before.Engine != after.Engine {
			return fmt.Errorf("database engine changed from %s to %s", before.Engine, after.Engine)
		}
		diff := dbmeta.Compare(before, after)
		if err = writeJSON(out, diff); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "database diff: %s, %d added, %d removed, %d changed\nwrote %s\n", diff.HighestRisk, len(diff.Added), len(diff.Removed), len(diff.Changed), out)
		return nil
	}}
	cmd.Flags().StringVarP(&out, "output", "o", "database-diff.json", "output JSON")
	return cmd
}

//go:embed report.html
var reportAssets embed.FS

var secureReportTemplate = template.Must(template.ParseFS(reportAssets, "report.html"))

func reportCmd() *cobra.Command {
	var state, out string
	cmd := &cobra.Command{Use: "report", Short: "Export a self-contained offline HTML report", RunE: func(cmd *cobra.Command, args []string) error {
		read := func(name string) json.RawMessage {
			b, _ := os.ReadFile(filepath.Join(state, name))
			if !json.Valid(b) {
				return json.RawMessage("null")
			}
			return b
		}
		data := struct{ Inventory, Drift json.RawMessage }{read("inventory.json"), read("drift.json")}
		dir := filepath.Dir(out)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = secureReportTemplate.ExecuteTemplate(f, "report.html", data); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
		return nil
	}}
	cmd.Flags().StringVar(&state, "state-dir", ".infrascout", "state directory")
	cmd.Flags().StringVarP(&out, "output", "o", "infrascout-report.html", "HTML output")
	return cmd
}
