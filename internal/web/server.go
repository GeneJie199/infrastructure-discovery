// Package web implements the local, zero-dependency InfraScout viewer.
// Static assets are embedded into the binary; data comes from
// inventory.json / snapshot.json / drift DiffReport JSON produced by the CLI.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

//go:embed static
var staticFS embed.FS

//go:embed demo/inventory.json demo/snapshot.json demo/drift.json demo/database.json demo/database-diff.json
var demoFS embed.FS

// Config controls the serve command.
type Config struct {
	Addr             string // listen address, e.g. 127.0.0.1:8080
	InventoryPath    string // path to inventory.json (optional)
	SnapshotPath     string // path to snapshot.json (optional)
	DriftPath        string // path to drift DiffReport JSON (optional)
	DatabasePath     string // path to database-metadata.json (optional)
	DatabaseDiffPath string // path to database drift JSON (optional)
	StateDir         string // managed baseline/current/drift/decisions directory
	Demo             bool   // load embedded fixture demo instead of files
	AllowRemote      bool   // permit a non-loopback listen address
}

// payload is the single JSON document consumed by the frontend.
// Documents stay raw so the UI always renders real CLI output fields.
type payload struct {
	GeneratedAt   string            `json:"generated_at"`
	Sources       map[string]string `json:"sources"`
	Inventory     json.RawMessage   `json:"inventory,omitempty"`
	Snapshot      json.RawMessage   `json:"snapshot,omitempty"`
	Drift         json.RawMessage   `json:"drift,omitempty"`
	Database      json.RawMessage   `json:"database,omitempty"`
	DatabaseDiff  json.RawMessage   `json:"database_diff,omitempty"`
	ReviewEnabled bool              `json:"review_enabled"`
}

// Server serves the embedded UI and the loaded JSON documents.
type Server struct {
	data payload
	mux  *http.ServeMux
	cfg  Config
	mu   sync.Mutex
}

// Load reads and validates the configured JSON documents.
// At least one document (or Demo) is required.
func Load(cfg Config) (*Server, error) {
	if cfg.StateDir != "" {
		if cfg.InventoryPath == "" {
			cfg.InventoryPath = filepath.Join(cfg.StateDir, "inventory.json")
		}
		if cfg.SnapshotPath == "" {
			cfg.SnapshotPath = filepath.Join(cfg.StateDir, "current.json")
		}
		if cfg.DriftPath == "" {
			cfg.DriftPath = filepath.Join(cfg.StateDir, "drift.json")
		}
		if cfg.DatabasePath == "" && fileExists(filepath.Join(cfg.StateDir, "database-current.json")) {
			cfg.DatabasePath = filepath.Join(cfg.StateDir, "database-current.json")
		}
		if cfg.DatabaseDiffPath == "" && fileExists(filepath.Join(cfg.StateDir, "database-diff.json")) {
			cfg.DatabaseDiffPath = filepath.Join(cfg.StateDir, "database-diff.json")
		}
	}
	s := &Server{
		cfg: cfg,
		data: payload{
			GeneratedAt:   time.Now().Format(time.RFC3339),
			Sources:       map[string]string{},
			ReviewEnabled: cfg.StateDir != "" && !cfg.Demo && !cfg.AllowRemote,
		},
	}
	if cfg.Demo {
		if err := s.loadDemo(); err != nil {
			return nil, err
		}
	} else {
		if cfg.InventoryPath == "" && cfg.SnapshotPath == "" && cfg.DriftPath == "" && cfg.DatabasePath == "" && cfg.DatabaseDiffPath == "" {
			return nil, fmt.Errorf("nothing to serve: pass --inventory/--snapshot/--drift or use --demo")
		}
		if err := s.loadFiles(cfg); err != nil {
			return nil, err
		}
	}
	s.mux = s.routes()
	return s, nil
}

func (s *Server) loadDemo() error {
	inv, err := demoFS.ReadFile("demo/inventory.json")
	if err != nil {
		return err
	}
	snap, err := demoFS.ReadFile("demo/snapshot.json")
	if err != nil {
		return err
	}
	drift, err := demoFS.ReadFile("demo/drift.json")
	if err != nil {
		return err
	}
	if err := validate(inv, &infrascout.Inventory{}); err != nil {
		return fmt.Errorf("demo inventory: %w", err)
	}
	if err := validate(snap, &infrascout.Snapshot{}); err != nil {
		return fmt.Errorf("demo snapshot: %w", err)
	}
	if err := validate(drift, &infrascout.DiffReport{}); err != nil {
		return fmt.Errorf("demo drift: %w", err)
	}
	database, err := demoFS.ReadFile("demo/database.json")
	if err != nil {
		return err
	}
	if err := validate(database, &dbmeta.Metadata{}); err != nil {
		return fmt.Errorf("demo database: %w", err)
	}
	s.data.Inventory = inv
	s.data.Snapshot = snap
	s.data.Drift = drift
	s.data.Database = database
	databaseDiff, err := demoFS.ReadFile("demo/database-diff.json")
	if err != nil {
		return err
	}
	if err := validate(databaseDiff, &dbmeta.Diff{}); err != nil {
		return fmt.Errorf("demo database diff: %w", err)
	}
	var demoReport infrascout.DiffReport
	var demoDatabaseDiff dbmeta.Diff
	if err := json.Unmarshal(drift, &demoReport); err != nil {
		return err
	}
	if err := json.Unmarshal(databaseDiff, &demoDatabaseDiff); err != nil {
		return err
	}
	dbmeta.MergeIntoInfraReport(&demoReport, demoDatabaseDiff)
	drift, err = json.Marshal(demoReport)
	if err != nil {
		return err
	}
	s.data.Drift = drift
	s.data.DatabaseDiff = databaseDiff
	s.data.Sources["inventory"] = "embedded demo"
	s.data.Sources["snapshot"] = "embedded demo"
	s.data.Sources["drift"] = "embedded demo"
	s.data.Sources["database"] = "embedded demo"
	s.data.Sources["database_diff"] = "embedded demo"
	return nil
}

func (s *Server) loadFiles(cfg Config) error {
	load := func(path string, into any, dst *json.RawMessage, key string) error {
		if path == "" {
			return nil
		}
		b, err := readJSONFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if err := validate(b, into); err != nil {
			return fmt.Errorf("%s %s: %w", key, path, err)
		}
		*dst = b
		s.data.Sources[key] = path
		return nil
	}
	if err := load(cfg.InventoryPath, &infrascout.Inventory{}, &s.data.Inventory, "inventory"); err != nil {
		return err
	}
	if err := load(cfg.SnapshotPath, &infrascout.Snapshot{}, &s.data.Snapshot, "snapshot"); err != nil {
		return err
	}
	if err := load(cfg.DriftPath, &infrascout.DiffReport{}, &s.data.Drift, "drift"); err != nil {
		return err
	}
	if err := load(cfg.DatabasePath, &dbmeta.Metadata{}, &s.data.Database, "database"); err != nil {
		return err
	}
	if err := load(cfg.DatabaseDiffPath, &dbmeta.Diff{}, &s.data.DatabaseDiff, "database_diff"); err != nil {
		return err
	}
	if cfg.StateDir != "" {
		s.data.Sources["decisions"] = filepath.Join(cfg.StateDir, "decisions.json")
	}
	return nil
}

func readJSONFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Tolerate UTF-8 BOM, mirroring the CLI diff reader.
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	return b, nil
}

func validate(b []byte, into any) error {
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", s.handleData)
	mux.HandleFunc("PATCH /api/reviews/{fingerprint}", s.handleReview)
	mux.HandleFunc("POST /api/reviews/{fingerprint}/promote", s.handlePromote)

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileSrv := http.FileServer(http.FS(sub))
	mux.Handle("/static/", http.StripPrefix("/static/", fileSrv))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		b, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index not found", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(b)
	})
	return mux
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	s.handleDataRequest(w, r)
}

func (s *Server) handleDataRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	data := s.data
	if !s.cfg.Demo {
		fresh, err := Load(s.cfg)
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "data reload failed: "+err.Error())
			return
		}
		data = fresh.data
	}
	revisionData, _ := json.Marshal(struct {
		Sources       map[string]string
		Inventory     json.RawMessage
		Snapshot      json.RawMessage
		Drift         json.RawMessage
		Database      json.RawMessage
		DatabaseDiff  json.RawMessage
		ReviewEnabled bool
	}{data.Sources, data.Inventory, data.Snapshot, data.Drift, data.Database, data.DatabaseDiff, data.ReviewEnabled})
	revision := fmt.Sprintf("\"%x\"", sha256.Sum256(revisionData))
	w.Header().Set("ETag", revision)
	if r != nil && r.Header.Get("If-None-Match") == revision {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	data.GeneratedAt = time.Now().Format(time.RFC3339)
	writeAPIJSON(w, data)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Handler returns the HTTP handler (used by tests and Serve).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
		s.mux.ServeHTTP(w, r)
	})
}

// Serve starts the HTTP server and blocks until it fails or is interrupted.
func Serve(cfg Config, logf func(format string, args ...any)) error {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8765"
	}
	if !cfg.AllowRemote {
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("refusing to listen on a non-loopback address (use --allow-remote to override)")
		}
	}
	srv, err := Load(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	if logf != nil {
		logf("InfraScout 查看器已启动: http://%s/ (Ctrl+C 退出)", ln.Addr().String())
		if cfg.AllowRemote {
			logf("安全边界: 远程监听仅提供只读查看，审核与基线提升 API 已强制禁用")
		}
		for k, v := range srv.data.Sources {
			logf("  已加载 %s: %s", k, v)
		}
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.Serve(ln)
}
