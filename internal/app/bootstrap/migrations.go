package bootstrap

import (
	"context"
	"io/fs"
	"sort"
	"strings"

	"fmt"
	"iam/migrations"
	"iam/pkg/logger"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationSource struct {
	module string
	files  fs.FS
}

const (
	migrationLockKey1 int32 = 20260422
	migrationLockKey2 int32 = 1
)

// RunMigrations executes every embedded *.up.sql on each startup.
// It intentionally does not store migration version/state in DB.
// Migration scripts must be idempotent (IF NOT EXISTS / conditional ALTER).
func RunMigrations(ctx context.Context, db *pgxpool.Pool, schema string) error {
	if db == nil {
		return fmt.Errorf("migration: db is nil")
	}

	conn, err := db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migration: acquire lock connection: %w", err)
	}
	defer conn.Release()

	// Ensure schema exists and set search_path
	if schema != "" {
		if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
			return fmt.Errorf("migration: create schema %s: %w", schema, err)
		}
		if _, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s", schema)); err != nil {
			return fmt.Errorf("migration: set search_path to %s: %w", schema, err)
		}
	}

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1, $2)`, migrationLockKey1, migrationLockKey2); err != nil {
		return fmt.Errorf("migration: acquire lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1, $2)`, migrationLockKey1, migrationLockKey2); unlockErr != nil {
			logger.SysWarn("app.migration", fmt.Sprintf("Failed to release advisory lock: %v", unlockErr))
		}
	}()

	sources := []migrationSource{
		{module: "iam", files: migrations.Files},
	}

	for _, source := range sources {
		if err := applyEmbeddedMigrations(ctx, conn, source); err != nil {
			return err
		}
	}

	return nil
}

func applyEmbeddedMigrations(ctx context.Context, db *pgxpool.Conn, source migrationSource) error {
	entries, err := fs.ReadDir(source.files, ".")
	if err != nil {
		return fmt.Errorf("migration: read %s embedded migrations: %w", source.module, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		queryBytes, err := fs.ReadFile(source.files, name)
		if err != nil {
			return fmt.Errorf("migration: read %s/%s: %w", source.module, name, err)
		}

		query := string(queryBytes)
		if strings.TrimSpace(query) == "" {
			continue
		}

		if _, err := db.Exec(ctx, query, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("migration: apply %s/%s: %w", source.module, name, err)
		}
	}

	return nil
}
