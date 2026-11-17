# Security Guide for OneNote MCP Server

This document outlines the security features and best practices for the OneNote MCP Server.

## Security Features Implemented

### 1. SQL Injection Prevention
- **Comprehensive Input Validation**: All SQL queries are validated before execution
- **Keyword Allowlisting**: Only safe SQL keywords are permitted (SELECT, FROM, WHERE, etc.)
- **Forbidden Operations**: INSERT, UPDATE, DELETE, DROP, and other dangerous operations are blocked
- **Pattern Detection**: Dangerous SQL constructs (semicolons, comments, system functions) are detected and blocked
- **Length Limits**: Query length is limited to prevent resource exhaustion
- **Multiple Statement Prevention**: Chained SQL execution is blocked

### 2. Driver Security
- **Driver Class Allowlisting**: Only pre-approved CData JDBC drivers are allowed
- **JAR File Validation**: Driver JAR files are validated for:
  - File existence and integrity
  - Valid file extensions (.jar)
  - Size limits (50MB maximum)
  - Path traversal prevention
  - Manifest validation
  - Entry count limits (prevents zip bombs)

### 3. Connection Management
- **Connection Limits**: Maximum of 10 concurrent connections
- **Rate Limiting**: Global and per-client connection rate limits
- **Connection Timeouts**: 30-second timeout for connection acquisition
- **Resource Tracking**: Active connection monitoring and statistics
- **Automatic Cleanup**: Connections are automatically released on completion

### 4. Input Validation & Sanitization
- **String Input Validation**: All configuration inputs are validated for length and dangerous characters
- **Path Validation**: File paths are validated to prevent traversal attacks
- **Log Path Security**: Log file paths are restricted to safe locations
- **Error Message Sanitization**: Sensitive information is removed from error messages

### 5. CSV Injection Protection
- **Formula Injection Prevention**: CSV fields starting with =, +, -, @ are neutralized
- **Content Sanitization**: Dangerous content and control characters are removed/replaced
- **Field Length Limits**: CSV fields are limited to 32KB to prevent resource exhaustion
- **Command Injection Detection**: Fields containing shell commands are neutralized

### 6. Secure Logging
- **Log Level Control**: Default log level set to 'info' (not 'debug')
- **Path Validation**: Log file paths are validated for security
- **Sensitive Data Masking**: Passwords, tokens, and secrets are masked in logs
- **Structured Logging**: Consistent timestamp and format for audit trails

## Security Configuration

### Driver Allowlist
The following driver classes are permitted:
- `cdata.jdbc.onenote.OneNoteDriver`
- `cdata.jdbc.salesforce.SalesforceDriver`
- `cdata.jdbc.sharepoint.SharePointDriver`
- `cdata.jdbc.excel.ExcelDriver`
- `cdata.jdbc.googledrive.GoogleDriveDriver`

To add new drivers, update the `ALLOWED_DRIVER_CLASSES` set in `SecurityValidator.java`.

### Connection Limits
- **Max Concurrent Connections**: 10
- **Connection Timeout**: 30 seconds
- **Rate Limit Window**: 1 minute
- **Max Connections per Window**: 100 (global), 25 (per client)

### File Size Limits
- **JAR Files**: 50MB maximum
- **CSV Fields**: 32KB maximum
- **SQL Queries**: 10,000 characters maximum

## Security Best Practices

### 1. Configuration Security
```properties
# Use specific paths, avoid wildcards
DriverPath=/path/to/trusted/cdata.jdbc.onenote.jar
DriverClass=cdata.jdbc.onenote.OneNoteDriver

# Use secure JDBC URLs
JdbcUrl=jdbc:onenote:InitiateOAuth=GETANDREFRESH;

# Restrict log file location
LogFile=/var/log/mcp-server/server.log
```

### 2. Deployment Security
- Run the server with minimal privileges
- Use a dedicated service account
- Restrict file system access
- Monitor connection usage and logs
- Keep CData drivers updated

### 3. Network Security
- Run on localhost only (`stdio` transport)
- Do not expose to untrusted networks
- Use secure authentication for OneNote access
- Monitor for unusual connection patterns

### 4. Monitoring & Auditing
- Monitor connection statistics: `config.getConnectionManager().getStatistics()`
- Review logs regularly for security events
- Track failed authentication attempts
- Monitor resource usage

## Known Limitations

### 1. Authentication
- **No built-in authentication**: The server relies on the underlying OneNote authentication
- **No user-level permissions**: All clients have the same access level
- **Recommendation**: Implement an authentication proxy if needed

### 2. Data Protection
- **No data classification**: All OneNote data is treated equally
- **No field-level encryption**: Data is transmitted as plain text CSV
- **Recommendation**: Use additional data loss prevention tools

### 3. Network Security
- **Plain text transport**: CSV data is not encrypted in transit
- **No TLS support**: Uses stdio transport only
- **Recommendation**: Use secure network controls and VPN if needed

## Incident Response

### Security Event Types
1. **SQL Injection Attempts**: Blocked malicious queries
2. **Driver Validation Failures**: Unauthorized JAR or driver class
3. **Connection Limit Exceeded**: Potential DoS attempts
4. **Path Traversal Attempts**: Unauthorized file access attempts
5. **CSV Injection Attempts**: Malicious formula injection

### Response Actions
1. Review security logs immediately
2. Check connection statistics for anomalies
3. Validate configuration files haven't been tampered with
4. Update driver allowlist if needed
5. Consider temporary rate limit adjustments

## Security Updates

To stay secure:
1. Monitor this repository for security updates
2. Keep CData JDBC drivers updated
3. Review security logs regularly
4. Update driver allowlists as needed
5. Test security controls periodically

## Reporting Security Issues

If you discover a security vulnerability:
1. Do not open a public issue
2. Email the security details to the maintainers
3. Include steps to reproduce
4. Provide suggested fixes if possible

---

**Last Updated**: December 2024
**Security Version**: 2.0