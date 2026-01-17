package com.cdata.mcp.auth;

/**
 * Defines specific permissions that can be granted to roles
 */
public enum Permission {
    /**
     * Read table and column metadata
     */
    READ_METADATA("read:metadata", "Read table and column metadata"),
    
    /**
     * Read actual data from tables
     */
    READ_DATA("read:data", "Read data from tables"),
    
    /**
     * Execute SQL queries
     */
    EXECUTE_QUERIES("execute:queries", "Execute SQL queries"),
    
    /**
     * View server statistics and monitoring data
     */
    VIEW_STATISTICS("view:statistics", "View server statistics"),
    
    /**
     * Manage API keys (create, revoke, list)
     */
    MANAGE_API_KEYS("manage:api-keys", "Manage API keys"),
    
    /**
     * View audit logs and access history
     */
    VIEW_AUDIT_LOGS("view:audit-logs", "View audit logs"),
    
    /**
     * Manage server configuration
     */
    MANAGE_CONFIGURATION("manage:configuration", "Manage server configuration");
    
    private final String code;
    private final String description;
    
    Permission(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    /**
     * Gets the permission code (used in API responses)
     * @return The permission code
     */
    public String getCode() {
        return code;
    }
    
    /**
     * Gets the human-readable description
     * @return The permission description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Gets a permission by code
     * @param code The permission code
     * @return The permission, or null if not found
     */
    public static Permission fromCode(String code) {
        if (code == null) {
            return null;
        }
        
        for (Permission permission : values()) {
            if (permission.code.equals(code)) {
                return permission;
            }
        }
        return null;
    }
}