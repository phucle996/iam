package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"controlplane/internal/domain/entity"
	"controlplane/pkg/errorx"
	"controlplane/pkg/id"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RbacRepository is the Postgres implementation.
//
// Schema (under iam schema):
//
//	roles             (id, name, level, description, created_at, updated_at)
//	permissions       (id, name, description, created_at)
//	role_permissions  (role_id, permission_id)
type RbacRepository struct {
	db *pgxpool.Pool
}

func NewRbacRepository(db *pgxpool.Pool) *RbacRepository {
	return &RbacRepository{db: db}
}

// ── Roles ─────────────────────────────────────────────────────────────────────

func (r *RbacRepository) GetRoleByName(ctx context.Context, name string) (*entity.RoleWithPermissions, error) {
	var role entity.Role
	err := r.db.QueryRow(ctx, `
		SELECT id, name, level, description, created_at, updated_at
		FROM roles WHERE name = $1`, name,
	).Scan(&role.ID, &role.Name, &role.Level, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrRoleNotFound
		}
		return nil, fmt.Errorf("rbac repo: get role by name: %w", err)
	}

	perms, err := r.permissionNamesForRole(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	return &entity.RoleWithPermissions{Role: &role, Permissions: perms}, nil
}

func (r *RbacRepository) ListRoleEntries(ctx context.Context) ([]*entity.RoleWithPermissions, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.id, r.name, r.level, r.description, r.created_at, r.updated_at, p.name
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		ORDER BY r.level ASC, r.name ASC, p.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("rbac repo: list role entries: %w", err)
	}
	defer rows.Close()

	entries := make([]*entity.RoleWithPermissions, 0)
	indexByRoleID := make(map[string]int)

	for rows.Next() {
		var (
			roleRow  entity.Role
			desc     sql.NullString
			permName sql.NullString
		)
		if err := rows.Scan(
			&roleRow.ID, &roleRow.Name, &roleRow.Level, &desc, &roleRow.CreatedAt, &roleRow.UpdatedAt, &permName,
		); err != nil {
			return nil, fmt.Errorf("rbac repo: scan role entry: %w", err)
		}
		if desc.Valid {
			roleRow.Description = desc.String
		}

		idx, ok := indexByRoleID[roleRow.ID]
		if !ok {
			roleCopy := roleRow
			entry := &entity.RoleWithPermissions{Role: &roleCopy}
			entries = append(entries, entry)
			indexByRoleID[roleRow.ID] = len(entries) - 1
			idx = len(entries) - 1
		}
		if permName.Valid && permName.String != "" {
			entries[idx].Permissions = append(entries[idx].Permissions, permName.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac repo: list role entries rows: %w", err)
	}

	return entries, nil
}

func (r *RbacRepository) ListRoles(ctx context.Context) ([]*entity.Role, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, level, description, created_at, updated_at
		FROM roles ORDER BY level ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("rbac repo: list roles: %w", err)
	}
	defer rows.Close()

	var result []*entity.Role
	for rows.Next() {
		var role entity.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Level, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("rbac repo: scan role: %w", err)
		}
		result = append(result, &role)
	}
	return result, rows.Err()
}

func (r *RbacRepository) GetRoleByID(ctx context.Context, roleID string) (*entity.Role, error) {
	var role entity.Role
	err := r.db.QueryRow(ctx, `
		SELECT id, name, level, description, created_at, updated_at
		FROM roles WHERE id = $1`, roleID,
	).Scan(&role.ID, &role.Name, &role.Level, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrRoleNotFound
		}
		return nil, fmt.Errorf("rbac repo: get role by id: %w", err)
	}
	return &role, nil
}

func (r *RbacRepository) CreateRole(ctx context.Context, role *entity.Role) error {
	if role.ID == "" {
		newID, err := id.Generate()
		if err != nil {
			return fmt.Errorf("rbac repo: gen id: %w", err)
		}
		role.ID = newID
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO roles (id, name, level, description, created_at, updated_at)
		VALUES ($1,$2,$3,$4,NOW(),NOW())`,
		role.ID, role.Name, role.Level, role.Description,
	)
	if err != nil {
		return fmt.Errorf("rbac repo: create role: %w", err)
	}
	return nil
}

func (r *RbacRepository) UpdateRole(ctx context.Context, role *entity.Role) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE roles
		SET name=$2, level=$3, description=$4, updated_at=NOW()
		WHERE id=$1`,
		role.ID, role.Name, role.Level, role.Description,
	)
	if err != nil {
		return fmt.Errorf("rbac repo: update role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrRoleNotFound
	}
	return nil
}

func (r *RbacRepository) DeleteRole(ctx context.Context, roleID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rbac repo: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1`, roleID,
	); err != nil {
		return fmt.Errorf("rbac repo: delete role_permissions: %w", err)
	}

	tag, err := tx.Exec(ctx, `DELETE FROM roles WHERE id = $1`, roleID)
	if err != nil {
		return fmt.Errorf("rbac repo: delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrRoleNotFound
	}
	return tx.Commit(ctx)
}

// ── Permissions ───────────────────────────────────────────────────────────────

func (r *RbacRepository) ListPermissions(ctx context.Context) ([]*entity.Permission, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, created_at
		FROM permissions ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("rbac repo: list permissions: %w", err)
	}
	defer rows.Close()

	var result []*entity.Permission
	for rows.Next() {
		var p entity.Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("rbac repo: scan permission: %w", err)
		}
		result = append(result, &p)
	}
	return result, rows.Err()
}

func (r *RbacRepository) GetPermissionByName(ctx context.Context, name string) (*entity.Permission, error) {
	var p entity.Permission
	err := r.db.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM permissions WHERE name = $1`, name,
	).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("rbac repo: get permission by name: %w", err)
	}
	return &p, nil
}

func (r *RbacRepository) GetPermissionByID(ctx context.Context, permID string) (*entity.Permission, error) {
	var p entity.Permission
	err := r.db.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM permissions WHERE id = $1`, permID,
	).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("rbac repo: get permission by id: %w", err)
	}
	return &p, nil
}

func (r *RbacRepository) CreatePermission(ctx context.Context, perm *entity.Permission) error {
	if perm.ID == "" {
		newID, err := id.Generate()
		if err != nil {
			return fmt.Errorf("rbac repo: gen id: %w", err)
		}
		perm.ID = newID
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO permissions (id, name, description, created_at)
		VALUES ($1,$2,$3,NOW())`,
		perm.ID, perm.Name, perm.Description,
	)
	if err != nil {
		return fmt.Errorf("rbac repo: create permission: %w", err)
	}
	return nil
}

func (r *RbacRepository) AssignPermission(ctx context.Context, roleID, permissionID string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		roleID, permissionID,
	)
	if err != nil {
		return fmt.Errorf("rbac repo: assign permission: %w", err)
	}
	return nil
}

func (r *RbacRepository) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM role_permissions WHERE role_id=$1 AND permission_id=$2`,
		roleID, permissionID,
	)
	if err != nil {
		return fmt.Errorf("rbac repo: revoke permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrPermissionNotFound
	}
	return nil
}

// ── private ───────────────────────────────────────────────────────────────────

func (r *RbacRepository) permissionNamesForRole(ctx context.Context, roleID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1 ORDER BY p.name ASC`, roleID,
	)
	if err != nil {
		return nil, fmt.Errorf("rbac repo: load perms for role: %w", err)
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("rbac repo: scan perm name: %w", err)
		}
		perms = append(perms, name)
	}
	return perms, rows.Err()
}
