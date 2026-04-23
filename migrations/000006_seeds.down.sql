DELETE FROM user_roles;
DELETE FROM role_permissions;
DELETE FROM permissions;
DELETE FROM roles;
DELETE FROM users;
-- Note: Audit logs and other operational data are NOT deleted by seed down for safety.
