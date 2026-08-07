package diff_test

import (
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/diff"
	"github.com/GeneJie199/infrastructure-discovery/internal/model"
)

func TestCompare_FiltersPIDAndStartedAt(t *testing.T) {
	base := model.Snapshot{
		SnapshotID: "snp_BASELINE00000000000000001",
		NoisePolicy: model.NoisePolicy{
			FilteredFields: []string{"attributes.pid", "attributes.startedAt"},
		},
		Resources: []model.Resource{
			{
				ResourceID:   "process.bin:shop/usr/sbin/nginx",
				ResourceType: "process.bin",
				DisplayName:  "nginx",
				Attributes: map[string]any{
					"pid":       1200,
					"startedAt": "2026-08-01T10:00:00Z",
					"exe":       "/usr/sbin/nginx",
					"user":      "nginx",
				},
			},
			{
				ResourceID:   "svc.systemd:shop/cron.service",
				ResourceType: "svc.systemd",
				DisplayName:  "cron",
				Attributes: map[string]any{
					"activeState": "inactive",
				},
			},
		},
	}
	cand := model.Snapshot{
		SnapshotID: "snp_CANDIDATE0000000000000001",
		NoisePolicy: model.NoisePolicy{
			FilteredFields: []string{"attributes.pid", "attributes.startedAt"},
		},
		Resources: []model.Resource{
			{
				ResourceID:   "process.bin:shop/usr/sbin/nginx",
				ResourceType: "process.bin",
				DisplayName:  "nginx",
				Attributes: map[string]any{
					"pid":       9999, // noise
					"startedAt": "2026-08-07T14:00:00Z", // noise
					"exe":       "/usr/sbin/nginx",
					"user":      "nginx",
				},
			},
			{
				ResourceID:   "svc.systemd:shop/nginx.service",
				ResourceType: "svc.systemd",
				DisplayName:  "nginx",
				Attributes: map[string]any{
					"activeState": "active",
				},
			},
		},
	}

	report := diff.Compare(base, cand)
	if len(report.Changed) != 0 {
		t.Fatalf("pid/startedAt should be ignored, changed=%#v", report.Changed)
	}
	if len(report.Added) != 1 || report.Added[0].ResourceID != "svc.systemd:shop/nginx.service" {
		t.Fatalf("added=%#v", report.Added)
	}
	if len(report.Removed) != 1 || report.Removed[0].ResourceID != "svc.systemd:shop/cron.service" {
		t.Fatalf("removed=%#v", report.Removed)
	}
	if report.UnchangedCount != 1 {
		t.Fatalf("unchanged=%d", report.UnchangedCount)
	}
}

func TestCompare_DetectsRealAttrChange(t *testing.T) {
	base := model.Snapshot{
		SnapshotID: "snp_A",
		Resources: []model.Resource{{
			ResourceID:   "svc.systemd:shop/nginx.service",
			ResourceType: "svc.systemd",
			DisplayName:  "nginx",
			Attributes:   map[string]any{"activeState": "active"},
		}},
		NoisePolicy: model.NoisePolicy{FilteredFields: model.DefaultNoiseFilteredFields},
	}
	cand := model.Snapshot{
		SnapshotID: "snp_B",
		Resources: []model.Resource{{
			ResourceID:   "svc.systemd:shop/nginx.service",
			ResourceType: "svc.systemd",
			DisplayName:  "nginx",
			Attributes:   map[string]any{"activeState": "failed"},
		}},
		NoisePolicy: model.NoisePolicy{FilteredFields: model.DefaultNoiseFilteredFields},
	}
	report := diff.Compare(base, cand)
	if len(report.Changed) != 1 {
		t.Fatalf("changed=%#v", report.Changed)
	}
	if report.Changed[0].Before["activeState"] != "active" || report.Changed[0].After["activeState"] != "failed" {
		t.Fatalf("change=%#v", report.Changed[0])
	}
}
