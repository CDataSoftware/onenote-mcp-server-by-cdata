package com.cdata.mcp.auth;

import java.util.EnumSet;
import java.util.Set;

/**
 * Defines roles and their associated permissions in the MCP server
 */
public enum Role {
    /**
     * Guest role - can only read basic metadata
     */
    GUEST(EnumSet.of(Permission.READ_METADATA)),
    
    /**
     * User role - can read data and execute queries
     */
    USER(EnumSet.of(Permission.READ_METADATA, Permission.READ_DATA, Permission.EXECUTE_QUERIES)),
    
    /**
     * Power user role - can read data, execute queries, and view statistics
     */
    POWER_USER(EnumSet.of(Permission.READ_METADATA, Permission.READ_DATA, Permission.EXECUTE_QUERIES, 
                         Permission.VIEW_STATISTICS)),
    
    /**
     * Admin role - full access to all operations
     */
    ADMIN(EnumSet.of(Permission.READ_METADATA, Permission.READ_DATA, Permission.EXECUTE_QUERIES,
                    Permission.VIEW_STATISTICS, Permission.MANAGE_API_KEYS, Permission.VIEW_AUDIT_LOGS,
                    Permission.MANAGE_CONFIGURATION));
    
    private final Set<Permission> permissions;
    
    Role(Set<Permission> permissions) {
        this.permissions = EnumSet.copyOf(permissions);
    }
    
    /**
     * Checks if this role has the specified permission
     * @param permission The permission to check
     * @return true if this role has the permission
     */
    public boolean hasPermission(Permission permission) {
        return permissions.contains(permission);
    }
    
    /**
     * Gets all permissions for this role
     * @return Unmodifiable set of permissions
     */
    public Set<Permission> getPermissions() {
        return EnumSet.copyOf(permissions);
    }
    
    /**
     * Checks if this role is at least as privileged as another role
     * @param other The role to compare against
     * @return true if this role has all permissions of the other role
     */
    public boolean includes(Role other) {
        return this.permissions.containsAll(other.permissions);
    }
    
    /**
     * Gets a role by name (case-insensitive)
     * @param name The role name
     * @return The role, or null if not found
     */
    public static Role fromString(String name) {
        if (name == null) {
            return null;
        }
        
        try {
            return Role.valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}