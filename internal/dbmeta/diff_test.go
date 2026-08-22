package dbmeta

import (
	"testing"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func TestCompareDetectsSchemaAndPrivilegeRisk(t *testing.T) {
	before := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "users", Columns: []Column{{Name: "id", DataType: "integer"}, {Name: "email", DataType: "text"}}}}}}, Privileges: []Object{{Schema: "app", Name: "SELECT", Type: "public.users"}}}
	after := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "users", Columns: []Column{{Name: "id", DataType: "bigint"}}}}}}}
	diff := Compare(before, after)
	if diff.HighestRisk != "CRITICAL" || len(diff.Removed) != 2 || len(diff.Changed) != 1 {
		t.Fatalf("unexpected diff: %+v", diff)
	}
}

func TestDatabaseDriftUsesUnifiedReviewAndSelectivePromotion(t *testing.T) {
	before := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "orders", Columns: []Column{{Name: "id", DataType: "uuid"}}}}}}}
	after := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "orders", Columns: []Column{{Name: "id", DataType: "bigint"}}}}}}}
	databaseDiff := Compare(before, after)
	report := infrascout.DiffReport{}
	MergeIntoInfraReport(&report, databaseDiff)
	infrascout.ApplyDecisions(&report, infrascout.DecisionSet{}, time.Now())
	if len(report.Changed) != 1 || report.Changed[0].Type != "database.column" || report.Changed[0].Fingerprint == "" {
		t.Fatalf("unified database drift=%+v", report)
	}
	if err := PromoteChange(&before, after, report.Changed[0].ID, "changed"); err != nil {
		t.Fatal(err)
	}
	if remaining := Compare(before, after); len(remaining.Changed)+len(remaining.Added)+len(remaining.Removed) != 0 {
		t.Fatalf("database promotion left drift=%+v", remaining)
	}
}

func TestCompareIncludesConstraintsAndRoles(t *testing.T) {
	before := Metadata{Engine: "postgresql", Constraints: []Constraint{{Schema: "public", Table: "orders", Name: "orders_pkey", Type: "PRIMARY KEY", Columns: []string{"id"}}}, Roles: []Object{{Name: "app_reader", Type: "ROLE", Detail: "login=true"}}}
	after := Metadata{Engine: "postgresql", Constraints: []Constraint{{Schema: "public", Table: "orders", Name: "orders_pkey", Type: "PRIMARY KEY", Columns: []string{"tenant_id", "id"}}}, Roles: []Object{{Name: "app_reader", Type: "ROLE", Detail: "login=true,superuser=true"}}}
	diff := Compare(before, after)
	if diff.Version != "infrascout.database-diff/v2" || len(diff.Changed) != 2 || diff.HighestRisk != "CRITICAL" {
		t.Fatalf("constraint/role diff=%+v", diff)
	}
}

func TestPromotingAddedTableKeepsColumnsPendingReview(t *testing.T) {
	baseline := Metadata{Engine: "postgresql"}
	current := Metadata{Engine: "postgresql", Schemas: []Schema{{
		Name: "public",
		Tables: []Table{{Schema: "public", Name: "orders", Columns: []Column{
			{Name: "id", DataType: "uuid"},
			{Name: "secret_note", DataType: "text"},
		}}},
	}}}
	if err := PromoteChange(&baseline, current, "dbmeta:table:public.orders", "added"); err != nil {
		t.Fatal(err)
	}
	remaining := Compare(baseline, current)
	if len(remaining.Added) != 2 {
		t.Fatalf("expected two columns to remain pending, got %+v", remaining.Added)
	}
	for _, item := range remaining.Added {
		if item.Kind != "column" {
			t.Fatalf("table promotion accepted unexpected child drift: %+v", remaining.Added)
		}
	}
}
