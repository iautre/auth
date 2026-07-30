package migrations

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

func TestAuthMigrationsStayInReservedVersionRange(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}

	found := 0
	seen := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		found++
		versionText := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil {
			t.Errorf("migration %q has invalid version: %v", entry.Name(), err)
			continue
		}
		if version < authMigrationMin || version > authMigrationMax {
			t.Errorf("migration %q is outside reserved auth range %d-%d", entry.Name(), authMigrationMin, authMigrationMax)
		}
		if previous, exists := seen[version]; exists {
			t.Errorf("migration version %d is duplicated by %q and %q", version, previous, entry.Name())
		}
		seen[version] = entry.Name()
	}
	if found == 0 {
		t.Fatal("no auth migrations found")
	}
}

func TestRegisterIsIdempotent(t *testing.T) {
	Register()
	Register()
}
