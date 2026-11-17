# Authentication & Authorization Guide

This document describes the authentication and authorization system for the OneNote MCP Server.

## Overview

The authentication system provides:
- **API Key Authentication**: Secure token-based authentication
- **Role-Based Access Control (RBAC)**: Granular permissions based on user roles
- **Session Management**: Secure session handling with configurable timeouts
- **Audit Trail**: Comprehensive logging of authentication events

## Configuration

### Enabling Authentication

Add these properties to your `.prp` configuration file:

```properties
# Enable authentication (default: false)
AuthRequired=true

# Session timeout in minutes (default: 60)
SessionTimeoutMinutes=120
```

### Default Admin Key

When authentication is first enabled, a default admin API key is automatically created and logged to the console:

```
Created default admin API key. Key: mcp_ABC123... (Store securely and change immediately!)
```

**⚠️ Security Warning**: Store this key securely and create new admin keys, then revoke the default one.

## API Keys

### API Key Format
- All API keys start with `mcp_` prefix
- 44 characters total length
- URL-safe Base64 encoded
- Example: `mcp_4Zq9wYxPmKcN7rT3vS8uE1bF6gH2jL5nM9pQ0sR`

### Creating API Keys

API keys can only be created by users with ADMIN role:

```java
// Example: Create a user-level API key that expires in 30 days
AuthenticationManager authManager = config.getAuthenticationManager();
Instant expiry = Instant.now().plus(30, ChronoUnit.DAYS);
String apiKey = authManager.createApiKey("production-user", Role.USER, expiry);
```

### Revoking API Keys

```java
// Revoke an API key by name
boolean revoked = authManager.revokeApiKey("production-user");
```

## Roles & Permissions

### Available Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **GUEST** | Read-only metadata access | `READ_METADATA` |
| **USER** | Standard user access | `READ_METADATA`, `READ_DATA`, `EXECUTE_QUERIES` |
| **POWER_USER** | Enhanced user access | All USER permissions + `VIEW_STATISTICS` |
| **ADMIN** | Full administrative access | All permissions |

### Permission Details

| Permission | Code | Description |
|------------|------|-------------|
| `READ_METADATA` | `read:metadata` | Read table and column metadata |
| `READ_DATA` | `read:data` | Read actual data from tables |
| `EXECUTE_QUERIES` | `execute:queries` | Execute SQL queries |
| `VIEW_STATISTICS` | `view:statistics` | View server statistics |
| `MANAGE_API_KEYS` | `manage:api-keys` | Create and revoke API keys |
| `VIEW_AUDIT_LOGS` | `view:audit-logs` | View authentication logs |
| `MANAGE_CONFIGURATION` | `manage:configuration` | Modify server settings |

## Session Management

### Session Lifecycle

1. **Authentication**: Client provides API key
2. **Session Creation**: Server creates session with timeout
3. **Token Response**: Client receives session token
4. **Request Authorization**: Client includes session token in subsequent requests
5. **Session Validation**: Server validates token and permissions
6. **Auto-Expiry**: Sessions expire after configured timeout
7. **Cleanup**: Expired sessions are automatically removed

### Session Properties

- **Session Timeout**: Configurable (default: 60 minutes)
- **Auto-Renewal**: Sessions extend automatically on use
- **Secure Tokens**: Cryptographically secure random tokens
- **Client Tracking**: IP address and user agent logged

## Usage Examples

### Basic Authentication Flow

```java
// 1. Get authentication manager
AuthenticationManager authManager = config.getAuthenticationManager();

// 2. Create client info
ClientInfo clientInfo = new ClientInfo("192.168.1.100", "MCP-Client/1.0", "client.example.com");

// 3. Authenticate with API key
AuthenticationResult result = authManager.authenticate(apiKey, clientInfo);

if (result.isSuccessful()) {
    String sessionToken = result.getSessionToken();
    Role userRole = result.getRole();
    
    // 4. Validate session for subsequent requests
    Session session = authManager.validateSession(sessionToken);
    
    // 5. Check permissions
    if (authManager.hasPermission(session, Permission.EXECUTE_QUERIES)) {
        // Execute query
    }
} else {
    // Handle authentication failure
    System.err.println("Authentication failed: " + result.getMessage());
}
```

### Creating and Managing API Keys

```java
AuthenticationManager authManager = config.getAuthenticationManager();

// Create different types of API keys
String guestKey = authManager.createApiKey("guest-access", Role.GUEST, 
                     Instant.now().plus(7, ChronoUnit.DAYS));

String userKey = authManager.createApiKey("app-user", Role.USER, 
                    Instant.now().plus(90, ChronoUnit.DAYS));

String adminKey = authManager.createApiKey("admin-backup", Role.ADMIN, null); // No expiry

// Revoke keys when needed
authManager.revokeApiKey("guest-access");
```

### Monitoring Authentication

```java
// Get authentication statistics
AuthenticationStats stats = authManager.getStats();
System.out.println("Active sessions: " + stats.getActiveSessions());
System.out.println("Active API keys: " + stats.getActiveApiKeys());
System.out.println("Total API keys: " + stats.getTotalApiKeys());

// Clean up expired sessions manually
authManager.cleanupExpiredSessions();
```

## Security Best Practices

### API Key Management

1. **Secure Storage**: Store API keys in secure configuration management systems
2. **Regular Rotation**: Rotate API keys regularly (recommended: 90 days)
3. **Principle of Least Privilege**: Assign minimal required role to each key
4. **Expiration**: Set appropriate expiration times for all keys
5. **Monitoring**: Monitor API key usage and revoke unused keys

### Session Security

1. **Timeout Configuration**: Set appropriate session timeouts for your environment
2. **Token Protection**: Treat session tokens as secrets
3. **Regular Cleanup**: Expired sessions are automatically cleaned up
4. **Client Validation**: Monitor for unusual client patterns

### Deployment Security

1. **HTTPS Only**: Always use HTTPS in production (when using HTTP transport)
2. **Network Isolation**: Deploy on secure networks with proper firewall rules
3. **Audit Logging**: Enable comprehensive audit logging
4. **Regular Updates**: Keep the server updated with latest security patches

## Integration with Tools

The authentication system integrates seamlessly with existing MCP tools:

```java
// Tools automatically respect user permissions
public class SecureRunQueryTool implements ITool {
    @Override
    public McpSchema.CallToolResult run(Map<String, Object> args) {
        // Session is automatically validated
        // Permissions are checked before execution
        // Audit events are logged
    }
}
```

## Troubleshooting

### Common Issues

1. **Authentication Required Error**
   - Ensure `AuthRequired=true` in configuration
   - Verify API key is provided and valid
   - Check API key hasn't expired or been revoked

2. **Permission Denied**
   - Verify user role has required permission
   - Check permission requirements for the operation
   - Ensure session hasn't expired

3. **Session Expired**
   - Sessions expire after configured timeout
   - Re-authenticate to get new session token
   - Consider increasing `SessionTimeoutMinutes`

### Debug Information

Enable debug logging to see authentication events:

```properties
# In your configuration
LogFile=/path/to/debug.log
```

Check logs for authentication events:
- Successful/failed authentication attempts
- Session creation and expiration
- Permission checks
- API key usage

## Migration from Unauthenticated

To migrate from an unauthenticated setup:

1. **Add Configuration**: Add `AuthRequired=true` to configuration
2. **Restart Server**: Server will create default admin key
3. **Create User Keys**: Use admin key to create user-specific keys
4. **Update Clients**: Configure clients with appropriate API keys
5. **Revoke Default**: Remove the default admin key once setup is complete

## Performance Considerations

- **Session Lookup**: O(1) session token validation
- **Permission Checks**: Minimal overhead (enum comparison)
- **Cleanup**: Automatic cleanup runs periodically
- **Memory Usage**: Sessions stored in memory (consider external storage for high-scale deployments)

---

For additional security features and enterprise deployment options, see the main [SECURITY.md](SECURITY.md) documentation.