package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOfflineReportEscapesInventoryValues(t *testing.T) {
	data := struct {
		Inventory json.RawMessage
		Drift     json.RawMessage
	}{
		Inventory: json.RawMessage(`{"collected_at":"now","detected_services":[{"kind":"web","name":"<img src=x onerror=alert(1)>","source":"test","confidence":1}]}`),
		Drift:     json.RawMessage(`{"highest_risk":"WARNING"}`),
	}
	var output bytes.Buffer
	if err := secureReportTemplate.ExecuteTemplate(&output, "report.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Contains(html, "<img src=x onerror") {
		t.Fatal("inventory value was emitted as executable HTML")
	}
	for _, required := range []string{"Content-Security-Policy", "const esc", "InfraScout 离线报告"} {
		if !strings.Contains(html, required) {
			t.Fatalf("report missing %q", required)
		}
	}
}
