package dbmeta

import "testing"

func TestCompareDetectsSchemaAndPrivilegeRisk(t *testing.T) {
	before := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "users", Columns: []Column{{Name: "id", DataType: "integer"}, {Name: "email", DataType: "text"}}}}}}, Privileges: []Object{{Schema: "app", Name: "SELECT", Type: "public.users"}}}
	after := Metadata{Engine: "postgresql", Schemas: []Schema{{Name: "public", Tables: []Table{{Schema: "public", Name: "users", Columns: []Column{{Name: "id", DataType: "bigint"}}}}}}}
	diff := Compare(before, after)
	if diff.HighestRisk != "CRITICAL" || len(diff.Removed) != 2 || len(diff.Changed) != 1 {
		t.Fatalf("unexpected diff: %+v", diff)
	}
}
