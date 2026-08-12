package dbmeta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Metadata struct {
	Version       string   `json:"version"`
	Engine        string   `json:"engine"`
	CollectedAt   string   `json:"collected_at"`
	ServerVersion string   `json:"server_version"`
	Schemas       []Schema `json:"schemas"`
	Indexes       []Object `json:"indexes"`
	Views         []Object `json:"views"`
	Triggers      []Object `json:"triggers"`
	Routines      []Object `json:"routines"`
	Privileges    []Object `json:"privileges"`
	Warnings      []string `json:"warnings,omitempty"`
}
type Schema struct {
	Name   string  `json:"name"`
	Tables []Table `json:"tables"`
}
type Table struct {
	Schema  string   `json:"schema"`
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}
type Column struct {
	Name     string `json:"name"`
	DataType string `json:"data_type"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
}
type Object struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
}

func Collect(ctx context.Context, engine, dsn string) (Metadata, error) {
	if dsn == "" {
		return Metadata{}, errors.New("database DSN is empty")
	}
	driver := engine
	if engine == "postgres" || engine == "postgresql" {
		driver = "pgx"
		engine = "postgresql"
	}
	if driver != "pgx" && driver != "mysql" {
		return Metadata{}, errors.New("engine must be postgres or mysql")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return Metadata{}, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Metadata{}, err
	}
	defer tx.Rollback()
	m := Metadata{Version: "infrascout.database/v1", Engine: engine, CollectedAt: time.Now().UTC().Format(time.RFC3339), Schemas: []Schema{}, Indexes: []Object{}, Views: []Object{}, Triggers: []Object{}, Routines: []Object{}, Privileges: []Object{}, Warnings: []string{}}
	if err = queryVersion(ctx, tx, engine, &m); err != nil {
		return m, err
	}
	if err = queryColumns(ctx, tx, engine, &m); err != nil {
		return m, err
	}
	queries := queriesFor(engine)
	collectObjects(ctx, tx, queries.indexes, "index", &m.Indexes, &m.Warnings)
	collectObjects(ctx, tx, queries.views, "view", &m.Views, &m.Warnings)
	collectObjects(ctx, tx, queries.triggers, "trigger", &m.Triggers, &m.Warnings)
	collectObjects(ctx, tx, queries.routines, "routine", &m.Routines, &m.Warnings)
	collectObjects(ctx, tx, queries.privileges, "privilege", &m.Privileges, &m.Warnings)
	return m, tx.Commit()
}
func queryVersion(ctx context.Context, tx *sql.Tx, engine string, m *Metadata) error {
	q := "SELECT version()"
	if engine == "mysql" {
		q = "SELECT @@version"
	}
	return tx.QueryRowContext(ctx, q).Scan(&m.ServerVersion)
}
func queryColumns(ctx context.Context, tx *sql.Tx, engine string, m *Metadata) error {
	q := `SELECT table_schema,table_name,column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema NOT IN ('information_schema','pg_catalog') ORDER BY table_schema,table_name,ordinal_position`
	if engine == "mysql" {
		q = `SELECT table_schema,table_name,column_name,column_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY table_schema,table_name,ordinal_position`
	}
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	schemaIndex := map[string]int{}
	tableIndex := map[string]map[string]int{}
	for rows.Next() {
		var s, t string
		var c Column
		var nullable string
		if err = rows.Scan(&s, &t, &c.Name, &c.DataType, &nullable, &c.Default); err != nil {
			return err
		}
		c.Nullable = strings.EqualFold(nullable, "YES")
		si, ok := schemaIndex[s]
		if !ok {
			si = len(m.Schemas)
			schemaIndex[s] = si
			tableIndex[s] = map[string]int{}
			m.Schemas = append(m.Schemas, Schema{Name: s, Tables: []Table{}})
		}
		ti, ok := tableIndex[s][t]
		if !ok {
			ti = len(m.Schemas[si].Tables)
			tableIndex[s][t] = ti
			m.Schemas[si].Tables = append(m.Schemas[si].Tables, Table{Schema: s, Name: t, Columns: []Column{}})
		}
		m.Schemas[si].Tables[ti].Columns = append(m.Schemas[si].Tables[ti].Columns, c)
	}
	return rows.Err()
}

type querySet struct{ indexes, views, triggers, routines, privileges string }

func queriesFor(engine string) querySet {
	if engine == "mysql" {
		return querySet{`SELECT table_schema,index_name,table_name,non_unique FROM information_schema.statistics WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') GROUP BY table_schema,index_name,table_name,non_unique`, `SELECT table_schema,table_name,'VIEW','' FROM information_schema.views WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')`, `SELECT trigger_schema,trigger_name,event_manipulation,event_object_table FROM information_schema.triggers`, `SELECT routine_schema,routine_name,routine_type,data_type FROM information_schema.routines WHERE routine_schema NOT IN ('mysql','sys')`, `SELECT grantee,privilege_type,'USER','' FROM information_schema.user_privileges`}
	}
	return querySet{`SELECT schemaname,indexname,tablename,indexdef FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog','information_schema')`, `SELECT table_schema,table_name,'VIEW',COALESCE(view_definition,'') FROM information_schema.views WHERE table_schema NOT IN ('pg_catalog','information_schema')`, `SELECT trigger_schema,trigger_name,event_manipulation,event_object_table FROM information_schema.triggers`, `SELECT routine_schema,routine_name,routine_type,data_type FROM information_schema.routines WHERE routine_schema NOT IN ('pg_catalog','information_schema')`, `SELECT grantee,privilege_type,table_schema,table_name FROM information_schema.table_privileges`}
}
func collectObjects(ctx context.Context, tx *sql.Tx, q, kind string, out *[]Object, warnings *[]string) {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("%s metadata: %v", kind, err))
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c, d any
		if err = rows.Scan(&a, &b, &c, &d); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("%s metadata row: %v", kind, err))
			return
		}
		*out = append(*out, Object{Schema: stringValue(a), Name: stringValue(b), Type: stringValue(c), Detail: stringValue(d)})
	}
}
func stringValue(v any) string {
	if v == nil {
		return ""
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(v)
}
