package com.cdata.mcp.auth;

/**
 * Statistics about the authentication system
 */
public class AuthenticationStats {
    private final int activeSessions;
    private final long activeApiKeys;
    private final long totalApiKeys;
    private final boolean authenticationRequired;
    
    public AuthenticationStats(int activeSessions, long activeApiKeys, long totalApiKeys, boolean authenticationRequired) {
        this.activeSessions = activeSessions;
        this.activeApiKeys = activeApiKeys;
        this.totalApiKeys = totalApiKeys;
        this.authenticationRequired = authenticationRequired;
    }
    
    /**
     * Gets the number of active sessions
     * @return Active session count
     */
    public int getActiveSessions() {
        return activeSessions;
    }
    
    /**
     * Gets the number of active (non-expired, enabled) API keys
     * @return Active API key count
     */
    public long getActiveApiKeys() {
        return activeApiKeys;
    }
    
    /**
     * Gets the total number of API keys (including disabled/expired)
     * @return Total API key count
     */
    public long getTotalApiKeys() {
        return totalApiKeys;
    }
    
    /**
     * Whether authentication is required for this server
     * @return true if authentication is required
     */
    public boolean isAuthenticationRequired() {
        return authenticationRequired;
    }
    
    @Override
    public String toString() {
        return String.format("AuthStats[sessions=%d, activeKeys=%d, totalKeys=%d, authRequired=%s]", 
                           activeSessions, activeApiKeys, totalApiKeys, authenticationRequired);
    }
}