package vault

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHealthReport(t *testing.T) {
	v, _ := newTestVault(t)
	p := v.Payload

	add := func(name, password string) {
		t.Helper()
		if err := p.AddEntry(DefaultFolder, name, Entry{Password: password}); err != nil {
			t.Fatalf("AddEntry(%s): %v", name, err)
		}
	}
	add("weak-common", "123456")              // common password
	add("weak-short", "abc")                  // shorter than 8
	add("strong-one", "Tr0ub4dor&3xKp!")      // fine
	add("shared-one", "ReusedPassw0rd!x")     // reused
	add("shared-two", "ReusedPassw0rd!x")     // reused
	add("stale-entry", "An0ther-Unique!Pass") // will be made old

	// Backdate one entry by 400 days.
	f := p.Folders[DefaultFolder]
	e := f.Entries["stale-entry"]
	e.UpdatedAt = time.Now().UTC().AddDate(0, 0, -400).Format(time.RFC3339)
	f.Entries["stale-entry"] = e

	report := p.HealthReport()
	if report.Total != 6 {
		t.Fatalf("total = %d, want 6", report.Total)
	}
	if report.Weak != 2 {
		t.Errorf("weak = %d, want 2 (%+v)", report.Weak, report.Issues)
	}
	if report.Reused != 2 {
		t.Errorf("reused = %d, want 2 (%+v)", report.Reused, report.Issues)
	}
	if report.Old != 1 {
		t.Errorf("old = %d, want 1 (%+v)", report.Old, report.Issues)
	}

	seen := map[string]string{}
	for _, issue := range report.Issues {
		seen[issue.Folder+"/"+issue.Name+"|"+issue.Reason] = issue.Detail
	}
	if d := seen["general/weak-common|weak"]; !strings.Contains(d, "common") {
		t.Errorf("weak-common detail = %q", d)
	}
	if d := seen["general/weak-short|weak"]; !strings.Contains(d, "shorter than 8") {
		t.Errorf("weak-short detail = %q", d)
	}
	if d := seen["general/shared-one|reused"]; !strings.Contains(d, "shared-two") {
		t.Errorf("reused detail = %q", d)
	}
	if d := seen["general/stale-entry|old"]; !strings.Contains(d, "400") {
		t.Errorf("old detail = %q", d)
	}
	if _, ok := seen["general/strong-one|weak"]; ok {
		t.Error("strong password must not be flagged")
	}

	// The report must never leak password values.
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"123456", "ReusedPassw0rd", "Tr0ub4dor", "An0ther-Unique"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("report leaks %q: %s", secret, raw)
		}
	}
}

func TestHealthReportEmptyVault(t *testing.T) {
	v, _ := newTestVault(t)
	report := v.Payload.HealthReport()
	if report.Total != 0 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v", report)
	}
}
