package com.cdata.mcp.auth;

import java.time.Instant;

/**
 * Contains information about the client making the request
 */
public class ClientInfo {
    private final String ipAddress;
    private final String userAgent;
    private final String hostName;
    private final Instant timestamp;
    
    public ClientInfo(String ipAddress, String userAgent, String hostName) {
        this.ipAddress = ipAddress != null ? ipAddress : "unknown";
        this.userAgent = userAgent != null ? userAgent : "unknown";
        this.hostName = hostName != null ? hostName : "unknown";
        this.timestamp = Instant.now();
    }
    
    /**
     * Gets the client IP address
     * @return The IP address
     */
    public String getIpAddress() {
        return ipAddress;
    }
    
    /**
     * Gets the client user agent string
     * @return The user agent
     */
    public String getUserAgent() {
        return userAgent;
    }
    
    /**
     * Gets the client hostname
     * @return The hostname
     */
    public String getHostName() {
        return hostName;
    }
    
    /**
     * Gets when this client info was created
     * @return The timestamp
     */
    public Instant getTimestamp() {
        return timestamp;
    }
    
    @Override
    public String toString() {
        return String.format("ClientInfo[ip=%s, host=%s, userAgent=%s]", 
                           ipAddress, hostName, 
                           userAgent.length() > 50 ? userAgent.substring(0, 50) + "..." : userAgent);
    }
}