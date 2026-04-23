# IAM Flow Documentation

This folder documents IAM runtime flows from the current backend implementation.

## Flow Index

1. [Register](./flow-auth-register.md)
2. [Activate Account](./flow-auth-activate.md)
3. [Login](./flow-auth-login.md)
4. [MFA Verify (Challenge Completion)](./flow-auth-mfa-verify.md)
5. [Refresh Token Rotation](./flow-auth-refresh.md)
6. [Forgot Password](./flow-auth-forgot-password.md)
7. [Reset Password](./flow-auth-reset-password.md)
8. [Logout](./flow-auth-logout.md)
9. [WhoAmI](./flow-auth-whoami.md)
10. [Device Management](./flow-device-management.md)
11. [MFA Self-Service Management](./flow-mfa-self-service.md)
12. [RBAC Admin and Cache Coherency](./flow-rbac-admin.md)
13. [Background Workers and Shutdown](./flow-background-workers.md)

## Notes

1. Sequence diagrams use Mermaid.
2. Flow docs focus on behavior currently present in code, including middleware and cookie contracts.
3. Error texts shown to client are intentionally generic for security-sensitive paths.
