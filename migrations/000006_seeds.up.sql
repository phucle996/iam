-- Initial Roles
INSERT INTO roles (id, name, level, description, created_at) VALUES
	(left(md5(random()::text || clock_timestamp()::text || 'user-role'), 26), 'user', 100, 'Standard baseline user', NOW()),
	(left(md5(random()::text || clock_timestamp()::text || 'root-role'), 26), 'root', 0, 'System root operator', NOW())
ON CONFLICT (name) DO NOTHING;

-- Initial Permissions
INSERT INTO permissions (id, name, slug, description, created_at) VALUES
    (left(md5(random()::text || clock_timestamp()::text || 'perm-user-read'), 26), 'iam:user:read', 'iam:user:read', 'Read user profiles', NOW()),
    (left(md5(random()::text || clock_timestamp()::text || 'perm-user-write'), 26), 'iam:user:write', 'iam:user:write', 'Modify user profiles', NOW()),
    (left(md5(random()::text || clock_timestamp()::text || 'perm-role-read'), 26), 'iam:role:read', 'iam:role:read', 'Read roles and permissions', NOW()),
    (left(md5(random()::text || clock_timestamp()::text || 'perm-role-assign'), 26), 'iam:role:assign', 'iam:role:assign', 'Assign roles to users', NOW())
ON CONFLICT (name) DO NOTHING;

-- Assign Permissions to Roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'iam:user:read'
WHERE r.name = 'user'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name IN (
	'iam:user:read',
	'iam:user:write',
	'iam:role:read',
	'iam:role:assign'
)
WHERE r.name = 'root'
ON CONFLICT DO NOTHING;

-- Bootstrap Root User
INSERT INTO users (
	id,
	username,
	email,
	phone,
	password_hash,
	security_level,
	status,
	status_reason,
	created_at,
	updated_at
) VALUES (
	left(md5(random()::text || clock_timestamp()::text || 'root-user'), 26),
	'root',
	'root@controlplane.local',
	NULL,
	'argon2id$v=19$m=65536,t=1,p=2$s1903CFSyFSsclrveeVRlQ$8XpGhCVA4M8OlC3fjJTqb51AxhocrOXFv++mS+VJqTk',
	0,
	'active',
	'bootstrap root account',
	NOW(),
	NOW()
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
JOIN roles r ON r.name = 'root'
WHERE u.username = 'root'
ON CONFLICT DO NOTHING;
