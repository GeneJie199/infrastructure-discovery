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
	Version       string       `json:"version"`
	Engine        string       `json:"engine"`
	DatabaseName  string       `json:"database_name,omitempty"`
	CollectedAt   string       `json:"collected_at"`
	ServerVersion string       `json:"server_version"`
	Schemas       []Schema     `json:"schemas"`
	Indexes       []Object     `json:"indexes"`
	Views         []Object     `json:"views"`
	Triggers      []Object     `json:"triggers"`
	Routines      []Object     `json:"routines"`
	Privileges    []Object     `json:"privileges"`
	Constraints   []Constraint `json:"constraints,omitempty"`
	Roles         []Object     `json:"roles,omitempty"`
	Warnings      []string     `json:"warnings,omitempty"`
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

type Constraint struct {
	Schema           string   `json:"schema"`
	Table            string   `json:"table"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Columns          []string `json:"columns"`
	ReferenceSchema  string   `json:"reference_schema,omitempty"`
	ReferenceTable   string   `json:"reference_table,omitempty"`
	ReferenceColumns []string `json:"reference_columns,omitempty"`
	UpdateRule       string   `json:"update_rule,omitempty"`
	DeleteRule       string   `json:"delete_rule,omitempty"`
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
	m := Metadata{Version: "infrascout.database/v2", Engine: engine, CollectedAt: time.Now().UTC().Format(time.RFC3339), Schemas: []Schema{}, Indexes: []Object{}, Views: []Object{}, Triggers: []Object{}, Routines: []Object{}, Privileges: []Object{}, Constraints: []Constraint{}, Roles: []Object{}, Warnings: []string{}}
	if err = queryVersion(ctx, tx, engine, &m); err != nil {
		return m, err
	}
	if err = queryColumns(ctx, tx, engine, &m); err != nil {
		return m, err
	}
	if err = queryDatabaseName(ctx, tx, engine, &m); err != nil {
		m.Warnings = append(m.Warnings, "database name metadata: "+err.Error())
	}
	queries := queriesFor(engine)
	collectObjects(ctx, tx, queries.indexes, "index", &m.Indexes, &m.Warnings)
	collectObjects(ctx, tx, queries.views, "view", &m.Views, &m.Warnings)
	collectObjects(ctx, tx, queries.triggers, "trigger", &m.Triggers, &m.Warnings)
	collectObjects(ctx, tx, queries.routines, "routine", &m.Routines, &m.Warnings)
	collectObjects(ctx, tx, queries.privileges, "privilege", &m.Privileges, &m.Warnings)
	collectObjects(ctx, tx, queries.roles, "role", &m.Roles, &m.Warnings)
	collectConstraints(ctx, tx, queries.constraints, &m.Constraints, &m.Warnings)
	return m, tx.Commit()
}

func queryDatabaseName(ctx context.Context, tx *sql.Tx, engine string, m *Metadata) error {
	query := "SELECT current_database()"
	if engine == "mysql" {
		query = "SELECT COALESCE(DATABASE(),'')"
	}
	return tx.QueryRowContext(ctx, query).Scan(&m.DatabaseName)
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
		q = `SELECT table_schema,table_name,column_name,column_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY table_schema,table_name,ordinal_position`
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

type querySet struct{ indexes, views, triggers, routines, privileges, roles, constraints string }

func queriesFor(engine string) querySet {
	if engine == "mysql" {
		return querySet{
			indexes:     `SELECT table_schema,index_name,table_name,IF(non_unique=0,'UNIQUE','INDEX') FROM information_schema.statistics WHERE table_schema = DATABASE() GROUP BY table_schema,index_name,table_name,non_unique`,
			views:       `SELECT table_schema,table_name,'VIEW','' FROM information_schema.views WHERE table_schema = DATABASE()`,
			triggers:    `SELECT trigger_schema,trigger_name,event_manipulation,event_object_table FROM information_schema.triggers WHERE trigger_schema = DATABASE()`,
			routines:    `SELECT routine_schema,routine_name,routine_type,data_type FROM information_schema.routines WHERE routine_schema = DATABASE()`,
			privileges:  `SELECT grantee,privilege_type,'GLOBAL',is_grantable FROM information_schema.user_privileges UNION ALL SELECT grantee,privilege_type,CONCAT(table_schema,'.',table_name),is_grantable FROM information_schema.table_privileges WHERE table_schema = DATABASE()`,
			roles:       `SELECT '',CONCAT(user,'@',host),'USER',CONCAT('locked=',account_locked) FROM mysql.user`,
			constraints: `SELECT tc.table_schema,tc.table_name,tc.constraint_name,tc.constraint_type,COALESCE(kcu.column_name,''),COALESCE(kcu.referenced_table_schema,''),COALESCE(kcu.referenced_table_name,''),COALESCE(kcu.referenced_column_name,''),COALESCE(rc.update_rule,''),COALESCE(rc.delete_rule,'') FROM information_schema.table_constraints tc LEFT JOIN information_schema.key_column_usage kcu ON tc.constraint_schema=kcu.constraint_schema AND tc.table_name=kcu.table_name AND tc.constraint_name=kcu.constraint_name LEFT JOIN information_schema.referential_constraints rc ON tc.constraint_schema=rc.constraint_schema AND tc.constraint_name=rc.constraint_name WHERE tc.table_schema = DATABASE() ORDER BY tc.table_schema,tc.table_name,tc.constraint_name,kcu.ordinal_position`,
		}
	}
	return querySet{
		indexes:     `SELECT schemaname,indexname,tablename,indexdef FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog','information_schema')`,
		views:       `SELECT table_schema,table_name,'VIEW',COALESCE(view_definition,'') FROM information_schema.views WHERE table_schema NOT IN ('pg_catalog','information_schema')`,
		triggers:    `SELECT trigger_schema,trigger_name,event_manipulation,event_object_table FROM information_schema.triggers WHERE trigger_schema NOT IN ('pg_catalog','information_schema')`,
		routines:    `SELECT routine_schema,routine_name,routine_type,data_type FROM information_schema.routines WHERE routine_schema NOT IN ('pg_catalog','information_schema')`,
		privileges:  `SELECT grantee,privilege_type,table_schema||'.'||table_name,is_grantable FROM information_schema.table_privileges WHERE table_schema NOT IN ('pg_catalog','information_schema') UNION ALL SELECT grantee,privilege_type,routine_schema||'.'||routine_name,is_grantable FROM information_schema.routine_privileges WHERE routine_schema NOT IN ('pg_catalog','information_schema')`,
		roles:       `SELECT '',rolname,'ROLE',CONCAT('login=',rolcanlogin,',superuser=',rolsuper,',createdb=',rolcreatedb) FROM pg_roles`,
		constraints: `SELECT tc.table_schema,tc.table_name,tc.constraint_name,tc.constraint_type,COALESCE(kcu.column_name,''),COALESCE(rkcu.table_schema,''),COALESCE(rkcu.table_name,''),COALESCE(rkcu.column_name,''),COALESCE(rc.update_rule,''),COALESCE(rc.delete_rule,'') FROM information_schema.table_constraints tc LEFT JOIN information_schema.key_column_usage kcu ON tc.constraint_schema=kcu.constraint_schema AND tc.table_name=kcu.table_name AND tc.constraint_name=kcu.constraint_name LEFT JOIN information_schema.referential_constraints rc ON tc.constraint_schema=rc.constraint_schema AND tc.constraint_name=rc.constraint_name LEFT JOIN information_schema.key_column_usage rkcu ON rkcu.constraint_catalog=rc.unique_constraint_catalog AND rkcu.constraint_schema=rc.unique_constraint_schema AND rkcu.constraint_name=rc.unique_constraint_name AND rkcu.ordinal_position=kcu.position_in_unique_constraint WHERE tc.table_schema NOT IN ('pg_catalog','information_schema') ORDER BY tc.table_schema,tc.table_name,tc.constraint_name,kcu.ordinal_position`,
	}
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

func collectConstraints(ctx context.Context, tx *sql.Tx, query string, out *[]Constraint, warnings *[]string) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("constraint metadata: %v", err))
		return
	}
	defer rows.Close()
	indexes := map[string]int{}
	for rows.Next() {
		var values [10]any
		pointers := make([]any, len(values))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("constraint metadata row: %v", err))
			return
		}
		parts := make([]string, len(values))
		for i := range values {
			parts[i] = stringValue(values[i])
		}
		key := strings.Join(parts[:4], "\x00")
		index, ok := indexes[key]
		if !ok {
			index = len(*out)
			indexes[key] = index
			*out = append(*out, Constraint{Schema: parts[0], Table: parts[1], Name: parts[2], Type: parts[3], ReferenceSchema: parts[5], ReferenceTable: parts[6], UpdateRule: parts[8], DeleteRule: parts[9]})
		}
		if parts[4] != "" {
			(*out)[index].Columns = appendUnique((*out)[index].Columns, parts[4])
		}
		if parts[7] != "" {
			(*out)[index].ReferenceColumns = appendUnique((*out)[index].ReferenceColumns, parts[7])
		}
	}
	if err = rows.Err(); err != nil {
		*warnings = append(*warnings, fmt.Sprintf("constraint metadata rows: %v", err))
	}
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
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
