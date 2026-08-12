package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLoadDemoServesAllDocuments(t *testing.T) {
	srv, err := Load(Config{Demo: true})
	if err != nil {
		t.Fatalf("Load demo: %v", err)
	}
	rec := get(t, srv.Handler(), "/api/data")
	if rec.Code != http.StatusOK {
		t.Fatalf("api status = %d", rec.Code)
	}
	var p payload
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("api response not JSON: %v", err)
	}
	if p.Inventory == nil || p.Snapshot == nil || p.Drift == nil || p.Database == nil {
		t.Fatal("demo should load inventory, snapshot, drift, and database metadata")
	}
	var drift infrascout.DiffReport
	if err := json.Unmarshal(p.Drift, &drift); err != nil {
		t.Fatalf("drift does not match DiffReport: %v", err)
	}
	if drift.HighestRisk != infrascout.SeverityCritical {
		t.Fatalf("demo highest_risk = %q, want CRITICAL", drift.HighestRisk)
	}
	var inv infrascout.Inventory
	if err := json.Unmarshal(p.Inventory, &inv); err != nil {
		t.Fatalf("inventory does not match Inventory: %v", err)
	}
	if inv.Hostname == "" || inv.Summary.Endpoints == 0 {
		t.Fatalf("demo inventory missing hostname/summary: %+v", inv.Summary)
	}
}

func TestStaticAssetsServed(t *testing.T) {
	srv, err := Load(Config{Demo: true})
	if err != nil {
		t.Fatalf("Load demo: %v", err)
	}
	for _, tc := range []struct {
		path    string
		want    string
		content string
	}{
		{"/", "InfraScout", "text/html"},
		{"/static/app.js", "/api/data", "javascript"},
		{"/static/style.css", ":root", "text/css"},
	} {
		rec := get(t, srv.Handler(), tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("GET %s missing %q", tc.path, tc.want)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.content) {
			t.Fatalf("GET %s content-type = %q", tc.path, ct)
		}
	}
}

func TestLoadRequiresInput(t *testing.T) {
	if _, err := Load(Config{}); err == nil {
		t.Fatal("Load without any input should fail")
	}
}

func TestLoadFromFiles(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inventory.json")
	inv := infrascout.Inventory{
		CollectedAt: "2026-08-08T10:14:22+08:00",
		Hostname:    "test-host",
		Resources:   []infrascout.Resource{},
	}
	b, _ := json.Marshal(inv)
	if err := os.WriteFile(invPath, b, 0o644); err != nil {
		t.Fatal(err)
	}

	srv, err := Load(Config{InventoryPath: invPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec := get(t, srv.Handler(), "/api/data")
	var p payload
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Drift != nil || p.Snapshot != nil {
		t.Fatal("only inventory was provided")
	}
	var got infrascout.Inventory
	if err := json.Unmarshal(p.Inventory, &got); err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "test-host" {
		t.Fatalf("hostname = %q", got.Hostname)
	}
	if p.Sources["inventory"] != invPath {
		t.Fatalf("sources = %+v", p.Sources)
	}
}

func TestFileModeReloadsChangedInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	write := func(host string) {
		b, _ := json.Marshal(infrascout.Inventory{Hostname: host})
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("before")
	srv, err := Load(Config{InventoryPath: path})
	if err != nil {
		t.Fatal(err)
	}
	write("after")
	rec := get(t, srv.Handler(), "/api/data")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"hostname":"after"`) {
		t.Fatalf("reload response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestDataEndpointUsesETagForUnchangedFacts(t *testing.T) {
	srv, err := Load(Config{Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	first := get(t, srv.Handler(), "/api/data")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("data endpoint did not return an ETag")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	request.Header.Set("If-None-Match", etag)
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		t.Fatalf("unchanged response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestDataReloadFailureIsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(path, []byte(`{"hostname":"before"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := Load(Config{InventoryPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := get(t, srv.Handler(), "/api/data")
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("reload response = %d %q %q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || !strings.Contains(body["error"], "data reload failed") {
		t.Fatalf("reload error = %#v, %v", body, err)
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "drift.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Config{DriftPath: bad}); err == nil {
		t.Fatal("invalid JSON should fail")
	}
}

func TestLoadToleratesBOM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inventory.json")
	b, _ := json.Marshal(infrascout.Inventory{Hostname: "bom-host"})
	b = append([]byte{0xEF, 0xBB, 0xBF}, b...)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Config{InventoryPath: p}); err != nil {
		t.Fatalf("BOM file should load: %v", err)
	}
}

// TestDemoInSyncWithExamples guards the embedded demo against drifting
// away from the canonical examples/v0.1 documents.
func TestDemoInSyncWithExamples(t *testing.T) {
	for _, name := range []string{"inventory.json", "snapshot.json", "drift.json", "database.json"} {
		embedded, err := demoFS.ReadFile("demo/" + name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		canonical, err := os.ReadFile(filepath.Join("..", "..", "examples", "v0.1", name))
		if err != nil {
			t.Fatalf("read examples/v0.1/%s: %v", name, err)
		}
		if string(embedded) != string(canonical) {
			t.Fatalf("demo/%s differs from examples/v0.1/%s — re-copy the example", name, name)
		}
	}
}

func TestServeRejectsRemoteAddress(t *testing.T) {
	if err := Serve(Config{Addr: "0.0.0.0:0", Demo: true}, nil); err == nil {
		t.Fatal("expected non-loopback address rejection")
	}
	if err := Serve(Config{Addr: "not-an-address", Demo: true}, nil); err == nil {
		t.Fatal("expected malformed address rejection")
	}
}

func TestUnknownPath404(t *testing.T) {
	srv, err := Load(Config{Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, srv.Handler(), "/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestManagedStateReviewAndSelectivePromotion(t *testing.T) {
	dir := t.TempDir()
	baseline := infrascout.Snapshot{Timestamp: "2026-08-12T09:00:00Z", Hostname: "node-a", Resources: []infrascout.Resource{{ID: "service:web", Type: "service", Metadata: map[string]any{"image": "v1"}}}}
	current := infrascout.Snapshot{Timestamp: "2026-08-12T10:00:00Z", Hostname: "node-a", Resources: []infrascout.Resource{{ID: "service:web", Type: "service", Metadata: map[string]any{"image": "v2"}}}}
	report := infrascout.Compare(baseline, current)
	infrascout.ApplyDecisions(&report, infrascout.DecisionSet{}, time.Now())
	write := func(name string, value any) {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("inventory.json", infrascout.Inventory{Hostname: "node-a"})
	write("baseline.json", baseline)
	write("current.json", current)
	write("drift.json", report)
	write("decisions.json", infrascout.DecisionSet{Version: infrascout.DecisionSetVersion, Decisions: []infrascout.DriftDecision{}})

	server, err := Load(Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := report.Changed[0].Fingerprint
	request := httptest.NewRequest(http.MethodPatch, "/api/reviews/"+fingerprint, strings.NewReader(`{"classification":"approved","actor":"platform-owner","note":"release rel-7"}`))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"classification":"approved"`) {
		t.Fatalf("review = %d %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/reviews/"+fingerprint+"/promote", nil)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("promote = %d %s", recorder.Code, recorder.Body.String())
	}
	var promoted infrascout.DiffReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &promoted); err != nil || len(promoted.Changed) != 0 {
		t.Fatalf("promoted report = %+v, %v", promoted, err)
	}
	var savedBaseline infrascout.Snapshot
	if err := readJSON(filepath.Join(dir, "baseline.json"), &savedBaseline); err != nil || savedBaseline.Resources[0].Metadata["image"] != "v2" {
		t.Fatalf("saved baseline = %+v, %v", savedBaseline, err)
	}
}

func TestReviewMutationDisabledForRemoteMode(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(infrascout.Inventory{Hostname: "node-a"})
	if err := os.WriteFile(filepath.Join(dir, "inventory.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"current.json", "drift.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := Load(Config{StateDir: dir, AllowRemote: true})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/reviews/drift_x", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("remote mutation = %d %s", recorder.Code, recorder.Body.String())
	}
}
