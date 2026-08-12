package configscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNginxRoutesAndOmitsDynamicUpstream(t *testing.T) {
	root := t.TempDir()
	config := `server {
  listen 443 ssl;
  server_name api.example.test;
  location /api/ { proxy_pass http://127.0.0.1:8080; }
  location /dynamic/ {
    proxy_pass http://$backend;
  }
}`
	if err := os.WriteFile(filepath.Join(root, "site.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	routes, warnings, err := ParseNginx(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("inline proxy_pass is intentionally unsupported, got %+v", routes)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected dynamic upstream warning, got %+v", warnings)
	}
}
