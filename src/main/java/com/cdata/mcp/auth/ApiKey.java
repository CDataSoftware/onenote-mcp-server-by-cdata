package com.cdata.mcp.auth;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents an API key with associated metadata and usage tracking
 */
public class ApiKey {
    private final String hashedValue;
    private final String name;
    private final Role role;
    private final Instant createdAt;
    private final Instant expiresAt;
    private volatile boolean active;
    private final AtomicLong usageCount;
    private volatile Instant lastUsedAt;
    private volatile ClientInfo lastUsedFrom;
    
    public ApiKey(String hashedValue, String name, Role role, Instant expiresAt) {
        this.hashedValue = hashedValue;
        this.name = name;
        this.role = role;
        this.createdAt = Instant.now();
        this.expiresAt = expiresAt;
        this.active = true;
        this.usageCount = new AtomicLong(0);
        this.lastUsedAt = null;
        this.lastUsedFrom = null;
    }
    
    /**
     * Gets the hashed API key value
     * @return The hashed value
     */
    public String getHashedValue() {
        return hashedValue;
    }
    
    /**
     * Gets the descriptive name for this API key
     * @return The name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Gets the role assigned to this API key
     * @return The role
     */
    public Role getRole() {
        return role;
    }
    
    /**
     * Gets when this API key was created
     * @return The creation time
     */
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    /**
     * Gets when this API key expires (null if no expiration)
     * @return The expiration time, or null
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    /**
     * Whether this API key is active
     * @return true if active
     */
    public boolean isActive() {
        return active;
    }
    
    /**
     * Sets the active status of this API key
     * @param active The new active status
     */
    public void setActive(boolean active) {
        this.active = active;
    }
    
    /**
     * Gets the number of times this API key has been used
     * @return The usage count
     */
    public long getUsageCount() {
        return usageCount.get();
    }
    
    /**
     * Gets when this API key was last used
     * @return The last usage time, or null if never used
     */
    public Instant getLastUsedAt() {
        return lastUsedAt;
    }
    
    /**
     * Gets client info from the last usage
     * @return The last client info, or null if never used
     */
    public ClientInfo getLastUsedFrom() {
        return lastUsedFrom;
    }
    
    /**
     * Records usage of this API key
     * @param clientInfo Information about the client using the key
     */
    public void recordUsage(ClientInfo clientInfo) {
        usageCount.incrementAndGet();
        lastUsedAt = Instant.now();
        lastUsedFrom = clientInfo;
    }
    
    /**
     * Checks if this API key has expired
     * @return true if expired
     */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }
    
    /**
     * Checks if this API key is valid (active and not expired)
     * @return true if valid
     */
    public boolean isValid() {
        return active && !isExpired();
    }
    
    @Override
    public String toString() {
        return String.format("ApiKey[name=%s, role=%s, active=%s, expires=%s, usage=%d]", 
                           name, role, active, expiresAt, usageCount.get());
    }
}