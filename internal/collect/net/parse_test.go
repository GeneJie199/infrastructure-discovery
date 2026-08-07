package net_test

import (
	"path/filepath"
	"testing"

	"github.com/GeneJie199/infrastructure-discovery/internal/collect/net"
)

func TestParseFromRoot_Fixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "host-sample")
	listeners, err := net.ParseFromRoot(root)
	if err != nil {
		t.Fatalf("ParseFromRoot: %v", err)
	}
	if len(listeners) < 2 {
		t.Fatalf("expected >=2 listeners, got %#v", listeners)
	}

	var found80, found22 bool
	for _, l := range listeners {
		if l.Proto == "tcp" && l.Port == 80 && l.PID == 1200 {
			found80 = true
			if l.ProcessExe != "/usr/sbin/nginx" {
				t.Fatalf("port 80 exe=%q", l.ProcessExe)
			}
		}
		if l.Proto == "tcp" && l.Port == 22 && l.PID == 800 {
			found22 = true
		}
		// Established connection must not appear as listener.
		if l.Port == 49600 {
			t.Fatalf("non-listen socket leaked: %#v", l)
		}
	}
	if !found80 || !found22 {
		t.Fatalf("missing listeners: 80=%v 22=%v all=%#v", found80, found22, listeners)
	}
}
