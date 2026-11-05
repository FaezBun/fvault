package vault

import (
	"errors"
	"testing"
)

func tagTestPayload(t *testing.T) *Payload {
	t.Helper()
	v, _ := newTestVault(t)
	entries := map[string]Entry{
		"app": {Password: "p1", Tags: []string{"prod", "web"}},
		"db":  {Password: "p2", Tags: []string{"prod"}},
		"cdn": {Password: "p3", Tags: []string{"prod", "web"}},
	}
	for name, entry := range entries {
		if err := v.Payload.AddEntry(DefaultFolder, name, entry); err != nil {
			t.Fatalf("AddEntry(%s): %v", name, err)
		}
	}
	return v.Payload
}

func TestTagCounts(t *testing.T) {
	p := tagTestPayload(t)
	counts := p.TagCounts()
	if len(counts) != 2 {
		t.Fatalf("counts = %+v", counts)
	}
	if counts[0].Name != "prod" || counts[0].Count != 3 {
		t.Fatalf("first count = %+v, want prod/3", counts[0])
	}
	if counts[1].Name != "web" || counts[1].Count != 2 {
		t.Fatalf("second count = %+v, want web/2", counts[1])
	}
}

func TestRenameTag(t *testing.T) {
	p := tagTestPayload(t)
	changed, err := p.RenameTag("prod", "production")
	if err != nil {
		t.Fatalf("RenameTag: %v", err)
	}
	if changed != 3 {
		t.Fatalf("changed = %d, want 3", changed)
	}
	counts := p.TagCounts()
	if counts[0].Name != "production" || counts[0].Count != 3 {
		t.Fatalf("counts = %+v", counts)
	}
	entry, ok := p.GetEntry(DefaultFolder, "app")
	if !ok {
		t.Fatal("app entry missing")
	}
	for _, tag := range entry.Tags {
		if tag == "prod" {
			t.Fatalf("old tag still present: %+v", entry.Tags)
		}
	}
	if last := p.Audit[len(p.Audit)-1]; last.Action != "tag.rename" {
		t.Fatalf("audit action = %q", last.Action)
	}
}

func TestRenameTagMergeDuplicates(t *testing.T) {
	p := tagTestPayload(t)
	// "cdn" already has both prod and web; renaming web -> prod must not
	// produce a duplicate tag.
	if _, err := p.RenameTag("web", "prod"); err != nil {
		t.Fatalf("RenameTag: %v", err)
	}
	entry, _ := p.GetEntry(DefaultFolder, "cdn")
	if len(entry.Tags) != 1 || entry.Tags[0] != "prod" {
		t.Fatalf("tags = %+v, want a single prod tag", entry.Tags)
	}
}

func TestRenameTagErrors(t *testing.T) {
	p := tagTestPayload(t)
	if _, err := p.RenameTag("missing", "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tag err = %v, want ErrNotFound", err)
	}
	if _, err := p.RenameTag("bad tag!", "ok"); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("invalid old tag err = %v, want ErrInvalidTag", err)
	}
	if _, err := p.RenameTag("prod", "bad new tag!"); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("invalid new tag err = %v, want ErrInvalidTag", err)
	}
}

func TestDeleteTag(t *testing.T) {
	p := tagTestPayload(t)
	changed, err := p.DeleteTag("web")
	if err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	if changed != 2 {
		t.Fatalf("changed = %d, want 2", changed)
	}
	for _, entry := range p.Folders[DefaultFolder].Entries {
		for _, tag := range entry.Tags {
			if tag == "web" {
				t.Fatalf("tag web still present on %+v", entry)
			}
		}
	}
	if last := p.Audit[len(p.Audit)-1]; last.Action != "tag.delete" {
		t.Fatalf("audit action = %q", last.Action)
	}
	if _, err := p.DeleteTag("web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v, want ErrNotFound", err)
	}
	if _, err := p.DeleteTag("bad tag!"); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("invalid tag err = %v, want ErrInvalidTag", err)
	}
}
