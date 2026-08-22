package dbmeta

import (
	"fmt"
	"strings"
)

// PromoteChange selectively applies one reviewed database metadata change.
func PromoteChange(baseline *Metadata, current Metadata, driftID, action string) error {
	if baseline == nil {
		return fmt.Errorf("database baseline is nil")
	}
	id := strings.TrimPrefix(driftID, "dbmeta:")
	kind := strings.SplitN(id, ":", 2)[0]
	switch kind {
	case "table":
		return promoteTable(baseline, current, id, action)
	case "column":
		return promoteColumn(baseline, current, id, action)
	case "constraint":
		return promoteConstraint(baseline, current, id, action)
	case "index":
		return promoteObjects(&baseline.Indexes, current.Indexes, kind, id, action)
	case "view":
		return promoteObjects(&baseline.Views, current.Views, kind, id, action)
	case "trigger":
		return promoteObjects(&baseline.Triggers, current.Triggers, kind, id, action)
	case "routine":
		return promoteObjects(&baseline.Routines, current.Routines, kind, id, action)
	case "privilege":
		return promoteObjects(&baseline.Privileges, current.Privileges, kind, id, action)
	case "role":
		return promoteObjects(&baseline.Roles, current.Roles, kind, id, action)
	default:
		return fmt.Errorf("unsupported database drift id %q", driftID)
	}
}

func promoteTable(baseline *Metadata, current Metadata, id, action string) error {
	removeTable(baseline, id)
	if action == "removed" {
		return nil
	}
	for _, schema := range current.Schemas {
		for _, table := range schema.Tables {
			if tableID(schema.Name, table.Name) == id {
				bi := ensureSchema(baseline, schema.Name)
				// Columns are separate review items. Promoting an added table must
				// not silently approve every column discovered beneath it.
				table.Columns = []Column{}
				baseline.Schemas[bi].Tables = append(baseline.Schemas[bi].Tables, table)
				return nil
			}
		}
	}
	return fmt.Errorf("database table %q not found in current metadata", id)
}

func removeTable(metadata *Metadata, id string) {
	for si := range metadata.Schemas {
		kept := metadata.Schemas[si].Tables[:0]
		for _, table := range metadata.Schemas[si].Tables {
			if tableID(metadata.Schemas[si].Name, table.Name) != id {
				kept = append(kept, table)
			}
		}
		metadata.Schemas[si].Tables = kept
	}
}

func promoteColumn(baseline *Metadata, current Metadata, id, action string) error {
	for si := range baseline.Schemas {
		for ti := range baseline.Schemas[si].Tables {
			columns := baseline.Schemas[si].Tables[ti].Columns[:0]
			for _, column := range baseline.Schemas[si].Tables[ti].Columns {
				if columnID(baseline.Schemas[si].Name, baseline.Schemas[si].Tables[ti].Name, column.Name) != id {
					columns = append(columns, column)
				}
			}
			baseline.Schemas[si].Tables[ti].Columns = columns
		}
	}
	if action == "removed" {
		return nil
	}
	for _, schema := range current.Schemas {
		for _, table := range schema.Tables {
			for _, column := range table.Columns {
				if columnID(schema.Name, table.Name, column.Name) == id {
					for si := range baseline.Schemas {
						if baseline.Schemas[si].Name == schema.Name {
							for ti := range baseline.Schemas[si].Tables {
								if baseline.Schemas[si].Tables[ti].Name == table.Name {
									baseline.Schemas[si].Tables[ti].Columns = append(baseline.Schemas[si].Tables[ti].Columns, column)
									return nil
								}
							}
						}
					}
					return fmt.Errorf("promote parent table before column %q", id)
				}
			}
		}
	}
	return fmt.Errorf("database column %q not found in current metadata", id)
}

func promoteConstraint(baseline *Metadata, current Metadata, id, action string) error {
	kept := baseline.Constraints[:0]
	for _, value := range baseline.Constraints {
		if constraintID(value) != id {
			kept = append(kept, value)
		}
	}
	baseline.Constraints = kept
	if action == "removed" {
		return nil
	}
	for _, value := range current.Constraints {
		if constraintID(value) == id {
			baseline.Constraints = append(baseline.Constraints, value)
			return nil
		}
	}
	return fmt.Errorf("database constraint %q not found in current metadata", id)
}

func promoteObjects(baseline *[]Object, current []Object, kind, id, action string) error {
	kept := (*baseline)[:0]
	for _, value := range *baseline {
		if objectID(kind, value) != id {
			kept = append(kept, value)
		}
	}
	*baseline = kept
	if action == "removed" {
		return nil
	}
	for _, value := range current {
		if objectID(kind, value) == id {
			*baseline = append(*baseline, value)
			return nil
		}
	}
	return fmt.Errorf("database %s %q not found in current metadata", kind, id)
}

func ensureSchema(metadata *Metadata, name string) int {
	for i := range metadata.Schemas {
		if metadata.Schemas[i].Name == name {
			return i
		}
	}
	metadata.Schemas = append(metadata.Schemas, Schema{Name: name, Tables: []Table{}})
	return len(metadata.Schemas) - 1
}

func tableID(schema, table string) string { return fmt.Sprintf("table:%s.%s", schema, table) }
func columnID(schema, table, column string) string {
	return fmt.Sprintf("column:%s.%s.%s", schema, table, column)
}
func constraintID(value Constraint) string {
	return fmt.Sprintf("constraint:%s.%s.%s", value.Schema, value.Table, value.Name)
}
func objectID(kind string, value Object) string {
	return fmt.Sprintf("%s:%s.%s.%s", kind, value.Schema, value.Name, value.Type)
}
