package com.cdata.mcp.tests;

import com.cdata.mcp.auth.*;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.*;

public class AuthenticationManagerTests {
    
    private AuthenticationManager authManager;
    private ClientInfo testClientInfo;
    
    @Before
    public void setUp() {
        // Test with authentication required and 10-minute sessions
        authManager = new AuthenticationManager(true, 10);
        testClientInfo = new ClientInfo("127.0.0.1", "test-client", "localhost");
    }
    
    @Test
    public void testDefaultAdminKeyCreation() {
        AuthenticationStats stats = authManager.getStats();
        assertEquals("Should have one API key (default admin)", 1, stats.getTotalApiKeys());
        assertEquals("Default admin key should be active", 1, stats.getActiveApiKeys());
    }
    
    @Test
    public void testCreateApiKey() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        
        assertNotNull("API key should be generated", apiKey);
        assertTrue("API key should start with mcp_", apiKey.startsWith("mcp_"));
        
        AuthenticationStats stats = authManager.getStats();
        assertEquals("Should have two API keys now", 2, stats.getTotalApiKeys());
        assertEquals("Both keys should be active", 2, stats.getActiveApiKeys());
    }
    
    @Test
    public void testSuccessfulAuthentication() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        
        assertTrue("Authentication should succeed", result.isSuccessful());
        assertNotNull("Session token should be provided", result.getSessionToken());
        assertEquals("Role should match", Role.USER, result.getRole());
    }
    
    @Test
    public void testFailedAuthenticationInvalidKey() {
        AuthenticationResult result = authManager.authenticate("invalid_key", testClientInfo);
        
        assertFalse("Authentication should fail", result.isSuccessful());
        assertNull("No session token should be provided", result.getSessionToken());
        assertNull("No role should be assigned", result.getRole());
        assertTrue("Error message should mention invalid key", 
                  result.getMessage().toLowerCase().contains("invalid"));
    }
    
    @Test
    public void testFailedAuthenticationMissingKey() {
        AuthenticationResult result = authManager.authenticate(null, testClientInfo);
        
        assertFalse("Authentication should fail", result.isSuccessful());
        assertTrue("Error message should mention required key", 
                  result.getMessage().toLowerCase().contains("required"));
    }
    
    @Test
    public void testSessionValidation() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        
        Session session = authManager.validateSession(result.getSessionToken());
        
        assertNotNull("Session should be valid", session);
        assertEquals("User name should match", "test-user", session.getUserName());
        assertEquals("Role should match", Role.USER, session.getRole());
        assertFalse("Session should not be expired", session.isExpired());
    }
    
    @Test
    public void testInvalidSessionToken() {
        Session session = authManager.validateSession("invalid_token");
        assertNull("Invalid session token should return null", session);
    }
    
    @Test
    public void testPermissionChecking() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        Session session = authManager.validateSession(result.getSessionToken());
        
        assertTrue("User should have READ_DATA permission", 
                  authManager.hasPermission(session, Permission.READ_DATA));
        assertFalse("User should not have MANAGE_API_KEYS permission", 
                   authManager.hasPermission(session, Permission.MANAGE_API_KEYS));
    }
    
    @Test
    public void testApiKeyRevocation() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        
        // Authenticate successfully first
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        assertTrue("Initial authentication should succeed", result.isSuccessful());
        
        // Revoke the API key
        boolean revoked = authManager.revokeApiKey("test-user");
        assertTrue("Revocation should succeed", revoked);
        
        // Try to authenticate again
        AuthenticationResult result2 = authManager.authenticate(apiKey, testClientInfo);
        assertFalse("Authentication should fail after revocation", result2.isSuccessful());
    }
    
    @Test
    public void testExpiredApiKey() {
        // Create API key that expires in the past
        Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
        String apiKey = authManager.createApiKey("expired-user", Role.USER, expiredTime);
        
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        
        assertFalse("Authentication should fail for expired key", result.isSuccessful());
        assertTrue("Error message should mention expiration", 
                  result.getMessage().toLowerCase().contains("expired"));
    }
    
    @Test
    public void testSessionLogout() {
        String apiKey = authManager.createApiKey("test-user", Role.USER, null);
        AuthenticationResult result = authManager.authenticate(apiKey, testClientInfo);
        
        boolean loggedOut = authManager.logout(result.getSessionToken());
        assertTrue("Logout should succeed", loggedOut);
        
        Session session = authManager.validateSession(result.getSessionToken());
        assertNull("Session should be invalid after logout", session);
    }
    
    @Test
    public void testSessionCleanup() {
        // Create authentication manager with very short session timeout
        AuthenticationManager shortTimeoutManager = new AuthenticationManager(true, 0);
        String apiKey = shortTimeoutManager.createApiKey("test-user", Role.USER, null);
        
        AuthenticationResult result = shortTimeoutManager.authenticate(apiKey, testClientInfo);
        assertTrue("Authentication should succeed", result.isSuccessful());
        
        // Wait a moment for session to expire
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Session should be expired
        Session session = shortTimeoutManager.validateSession(result.getSessionToken());
        assertNull("Session should be expired", session);
    }
    
    @Test
    public void testAuthenticationDisabled() {
        // Create manager with authentication disabled
        AuthenticationManager noAuthManager = new AuthenticationManager(false, 10);
        
        AuthenticationResult result = noAuthManager.authenticate(null, testClientInfo);
        
        assertTrue("Authentication should succeed when disabled", result.isSuccessful());
        assertNotNull("Session token should be provided", result.getSessionToken());
        assertEquals("Role should be USER", Role.USER, result.getRole());
    }
    
    @Test
    public void testRolePermissions() {
        // Test different roles have correct permissions
        assertTrue("ADMIN should have MANAGE_API_KEYS", Role.ADMIN.hasPermission(Permission.MANAGE_API_KEYS));
        assertTrue("USER should have READ_DATA", Role.USER.hasPermission(Permission.READ_DATA));
        assertFalse("GUEST should not have READ_DATA", Role.GUEST.hasPermission(Permission.READ_DATA));
        assertTrue("GUEST should have READ_METADATA", Role.GUEST.hasPermission(Permission.READ_METADATA));
    }
    
    @Test
    public void testRoleInclusion() {
        assertTrue("ADMIN should include USER permissions", Role.ADMIN.includes(Role.USER));
        assertTrue("USER should include GUEST permissions", Role.USER.includes(Role.GUEST));
        assertFalse("GUEST should not include USER permissions", Role.GUEST.includes(Role.USER));
    }
    
    @Test
    public void testAuthenticationStats() {
        // Create some API keys and sessions
        authManager.createApiKey("user1", Role.USER, null);
        authManager.createApiKey("user2", Role.ADMIN, null);
        
        String apiKey = authManager.createApiKey("user3", Role.USER, null);
        authManager.authenticate(apiKey, testClientInfo);
        
        AuthenticationStats stats = authManager.getStats();
        
        assertEquals("Should have 4 total API keys (including default)", 4, stats.getTotalApiKeys());
        assertEquals("Should have 4 active API keys", 4, stats.getActiveApiKeys());
        assertEquals("Should have 1 active session", 1, stats.getActiveSessions());
        assertTrue("Authentication should be required", stats.isAuthenticationRequired());
    }
}