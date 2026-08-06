package systempolicy

import "strconv"

type MigrationPlan struct {
	Status   string   `json:"status"`
	Changes  []string `json:"changes,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func PlanMigration(sourceSchemaVersion int, sourceTemplateVersion, sourceCRSVersion string, target Template) MigrationPlan {
	plan := MigrationPlan{Status: "READY"}
	if sourceSchemaVersion != target.SchemaVersion {
		source := "unset"
		if sourceSchemaVersion != 0 {
			source = strconv.Itoa(sourceSchemaVersion)
		}
		plan.Changes = append(plan.Changes, "schema "+source+" -> "+strconv.Itoa(target.SchemaVersion))
	}
	if sourceTemplateVersion != target.Version {
		plan.Changes = append(plan.Changes, "template "+sourceTemplateVersion+" -> "+target.Version)
	}
	if sourceCRSVersion != target.CRSVersion {
		plan.Changes = append(plan.Changes, "CRS "+sourceCRSVersion+" -> "+target.CRSVersion)
		plan.Warnings = append(plan.Warnings,
			"CRS rule IDs, exclusions, plugins and engine compatibility must be checked by the release verification pipeline",
		)
	}
	return plan
}
