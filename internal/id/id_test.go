package id_test

import (
	"strings"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/id"
)

func TestResourceIDs(t *testing.T) {
	if got := id.Host("shop-prod-api-01"); got != "host:shop-prod-api-01" {
		t.Fatalf("%s", got)
	}
	if got := id.SystemdService("shop-prod-api-01", "nginx.service"); got != "svc.systemd:shop-prod-api-01/nginx.service" {
		t.Fatalf("%s", got)
	}
	if got := id.ProcessBin("shop-prod-api-01", "/usr/sbin/nginx"); got != "process.bin:shop-prod-api-01/usr/sbin/nginx" {
		t.Fatalf("%s", got)
	}
	if got := id.NetListener("shop-prod-api-01", "tcp", "0.0.0.0", 80); got != "net.listener:shop-prod-api-01/tcp/*/80" {
		t.Fatalf("%s", got)
	}
	if strings.Contains(id.ProcessBin("h", "/bin/a"), "pid") {
		t.Fatal("pid leaked into process id")
	}
}
