package com.cdata.mcp.auth;

import java.time.Instant;

/**
 * Represents an active user session
 */
public class Session {
    private final String sessionToken;
    private final String userName;
    private final Role role;
    private final Instant expiresAt;
    private final ClientInfo clientInfo;
    private final Instant createdAt;
    private volatile Instant lastAccessAt;
    
    public Session(String sessionToken, String userName, Role role, Instant expiresAt, ClientInfo clientInfo) {
        this.sessionToken = sessionToken;
        this.userName = userName;
        this.role = role;
        this.expiresAt = expiresAt;
        this.clientInfo = clientInfo;
        this.createdAt = Instant.now();
        this.lastAccessAt = this.createdAt;
    }
    
    /**
     * Gets the session token
     * @return The session token
     */
    public String getSessionToken() {
        return sessionToken;
    }
    
    /**
     * Gets the user name associated with this session
     * @return The user name
     */
    public String getUserName() {
        return userName;
    }
    
    /**
     * Gets the role for this session
     * @return The user role
     */
    public Role getRole() {
        return role;
    }
    
    /**
     * Gets when this session expires
     * @return The expiration time
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    /**
     * Gets client information for this session
     * @return The client info
     */
    public ClientInfo getClientInfo() {
        return clientInfo;
    }
    
    /**
     * Gets when this session was created
     * @return The creation time
     */
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    /**
     * Gets when this session was last accessed
     * @return The last access time
     */
    public Instant getLastAccessAt() {
        return lastAccessAt;
    }
    
    /**
     * Updates the last access time to now
     */
    public void updateLastAccess() {
        this.lastAccessAt = Instant.now();
    }
    
    /**
     * Checks if this session has expired
     * @return true if the session has expired
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
    
    /**
     * Checks if this session has the specified permission
     * @param permission The permission to check
     * @return true if the session's role has the permission
     */
    public boolean hasPermission(Permission permission) {
        return role.hasPermission(permission);
    }
    
    /**
     * Gets the session duration in seconds
     * @return Session duration from creation to last access
     */
    public long getDurationSeconds() {
        return lastAccessAt.getEpochSecond() - createdAt.getEpochSecond();
    }
    
    @Override
    public String toString() {
        return String.format("Session[token=%s, user=%s, role=%s, expires=%s]", 
                           sessionToken.substring(0, Math.min(8, sessionToken.length())) + "...", 
                           userName, role, expiresAt);
    }
}