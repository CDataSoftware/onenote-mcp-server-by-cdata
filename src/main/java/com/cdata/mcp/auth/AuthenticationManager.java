package com.cdata.mcp.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages authentication and authorization for the MCP server
 * Supports API key-based authentication with role-based access control
 */
public class AuthenticationManager {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManager.class);
    
    // API key storage (in production, this should be backed by a database)
    private final Map<String, ApiKey> apiKeys = new ConcurrentHashMap<>();
    
    // Active sessions
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    
    // Configuration
    private final long sessionTimeoutMinutes;
    private final boolean authenticationRequired;
    
    public AuthenticationManager(boolean authenticationRequired, long sessionTimeoutMinutes) {
        this.authenticationRequired = authenticationRequired;
        this.sessionTimeoutMinutes = sessionTimeoutMinutes;
        
        // Initialize with default admin key if none exist (for first setup)
        if (authenticationRequired && apiKeys.isEmpty()) {
            createDefaultAdminKey();
        }
        
        logger.info("Authentication manager initialized - Required: {}, Session timeout: {} minutes", 
                   authenticationRequired, sessionTimeoutMinutes);
    }
    
    /**
     * Authenticates a client using an API key
     * @param apiKeyValue The API key provided by the client
     * @param clientInfo Additional client information (IP, user agent, etc.)
     * @return Authentication result with session token if successful
     */
    public AuthenticationResult authenticate(String apiKeyValue, ClientInfo clientInfo) {
        if (!authenticationRequired) {
            // Create anonymous session when auth is disabled
            String sessionToken = generateSessionToken();
            Session session = new Session(sessionToken, "anonymous", Role.USER, 
                                        Instant.now().plus(sessionTimeoutMinutes, ChronoUnit.MINUTES), 
                                        clientInfo);
            sessions.put(sessionToken, session);
            return new AuthenticationResult(true, sessionToken, Role.USER, "Authentication disabled");
        }
        
        if (apiKeyValue == null || apiKeyValue.trim().isEmpty()) {
            logger.warn("Authentication failed: Missing API key from {}", clientInfo.getIpAddress());
            return new AuthenticationResult(false, null, null, "API key required");
        }
        
        // Hash the provided API key for lookup
        String hashedKey = hashApiKey(apiKeyValue);
        ApiKey apiKey = apiKeys.get(hashedKey);
        
        if (apiKey == null) {
            logger.warn("Authentication failed: Invalid API key from {}", clientInfo.getIpAddress());
            return new AuthenticationResult(false, null, null, "Invalid API key");
        }
        
        if (!apiKey.isActive()) {
            logger.warn("Authentication failed: Disabled API key '{}' from {}", 
                       apiKey.getName(), clientInfo.getIpAddress());
            return new AuthenticationResult(false, null, null, "API key disabled");
        }
        
        if (apiKey.isExpired()) {
            logger.warn("Authentication failed: Expired API key '{}' from {}", 
                       apiKey.getName(), clientInfo.getIpAddress());
            return new AuthenticationResult(false, null, null, "API key expired");
        }
        
        // Create session
        String sessionToken = generateSessionToken();
        Instant expiresAt = Instant.now().plus(sessionTimeoutMinutes, ChronoUnit.MINUTES);
        Session session = new Session(sessionToken, apiKey.getName(), apiKey.getRole(), expiresAt, clientInfo);
        sessions.put(sessionToken, session);
        
        // Update API key usage
        apiKey.recordUsage(clientInfo);
        
        logger.info("Authentication successful: User '{}' with role '{}' from {}", 
                   apiKey.getName(), apiKey.getRole(), clientInfo.getIpAddress());
        
        return new AuthenticationResult(true, sessionToken, apiKey.getRole(), "Authentication successful");
    }
    
    /**
     * Validates a session token and returns the active session
     * @param sessionToken The session token to validate
     * @return The active session, or null if invalid/expired
     */
    public Session validateSession(String sessionToken) {
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            return null;
        }
        
        Session session = sessions.get(sessionToken);
        if (session == null) {
            return null;
        }
        
        if (session.isExpired()) {
            sessions.remove(sessionToken);
            logger.debug("Session expired and removed: {}", sessionToken);
            return null;
        }
        
        // Update last access time
        session.updateLastAccess();
        return session;
    }
    
    /**
     * Checks if a session has the required permission for an operation
     * @param session The active session
     * @param requiredPermission The permission required for the operation
     * @return true if the session has the required permission
     */
    public boolean hasPermission(Session session, Permission requiredPermission) {
        if (session == null) {
            return false;
        }
        
        return session.getRole().hasPermission(requiredPermission);
    }
    
    /**
     * Creates a new API key
     * @param name Descriptive name for the API key
     * @param role Role assigned to the API key
     * @param expiresAt Expiration time (null for no expiration)
     * @return The generated API key value (store securely - cannot be retrieved later)
     */
    public String createApiKey(String name, Role role, Instant expiresAt) {
        String apiKeyValue = generateApiKey();
        String hashedKey = hashApiKey(apiKeyValue);
        
        ApiKey apiKey = new ApiKey(hashedKey, name, role, expiresAt);
        apiKeys.put(hashedKey, apiKey);
        
        logger.info("API key created: '{}' with role '{}'", name, role);
        return apiKeyValue;
    }
    
    /**
     * Revokes an API key by name
     * @param name The name of the API key to revoke
     * @return true if the key was found and revoked
     */
    public boolean revokeApiKey(String name) {
        for (Map.Entry<String, ApiKey> entry : apiKeys.entrySet()) {
            if (entry.getValue().getName().equals(name)) {
                entry.getValue().setActive(false);
                logger.info("API key revoked: '{}'", name);
                return true;
            }
        }
        return false;
    }
    
    /**
     * Logs out a session
     * @param sessionToken The session token to invalidate
     * @return true if the session was found and removed
     */
    public boolean logout(String sessionToken) {
        Session session = sessions.remove(sessionToken);
        if (session != null) {
            logger.info("Session logged out: User '{}' from {}", 
                       session.getUserName(), session.getClientInfo().getIpAddress());
            return true;
        }
        return false;
    }
    
    /**
     * Cleans up expired sessions
     */
    public void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int initialSize = sessions.size();
        
        sessions.entrySet().removeIf(entry -> 
            entry.getValue().getExpiresAt().isBefore(now));
        
        int removed = initialSize - sessions.size();
        if (removed > 0) {
            logger.debug("Cleaned up {} expired sessions", removed);
        }
    }
    
    /**
     * Gets statistics about active sessions and API keys
     * @return Authentication statistics
     */
    public AuthenticationStats getStats() {
        cleanupExpiredSessions(); // Clean up before reporting stats
        
        long activeApiKeys = apiKeys.values().stream()
            .filter(ApiKey::isActive)
            .filter(key -> !key.isExpired())
            .count();
            
        return new AuthenticationStats(
            sessions.size(),
            activeApiKeys,
            apiKeys.size(),
            authenticationRequired
        );
    }
    
    private void createDefaultAdminKey() {
        String defaultKey = createApiKey("default-admin", Role.ADMIN, null);
        logger.warn("Created default admin API key. Key: {} (Store securely and change immediately!)", defaultKey);
    }
    
    private String generateApiKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return "mcp_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    private String generateSessionToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    private String hashApiKey(String apiKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(apiKey.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}