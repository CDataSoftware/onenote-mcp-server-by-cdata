package com.cdata.mcp.auth;

/**
 * Result of an authentication attempt
 */
public class AuthenticationResult {
    private final boolean successful;
    private final String sessionToken;
    private final Role role;
    private final String message;
    
    public AuthenticationResult(boolean successful, String sessionToken, Role role, String message) {
        this.successful = successful;
        this.sessionToken = sessionToken;
        this.role = role;
        this.message = message;
    }
    
    /**
     * Whether authentication was successful
     * @return true if authentication succeeded
     */
    public boolean isSuccessful() {
        return successful;
    }
    
    /**
     * Gets the session token (only available if authentication succeeded)
     * @return The session token, or null if authentication failed
     */
    public String getSessionToken() {
        return sessionToken;
    }
    
    /**
     * Gets the role assigned to the authenticated user
     * @return The user role, or null if authentication failed
     */
    public Role getRole() {
        return role;
    }
    
    /**
     * Gets a message describing the authentication result
     * @return The result message
     */
    public String getMessage() {
        return message;
    }
    
    @Override
    public String toString() {
        return String.format("AuthenticationResult[successful=%s, role=%s, message=%s]", 
                           successful, role, message);
    }
}