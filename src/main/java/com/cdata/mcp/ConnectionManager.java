package com.cdata.mcp;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages database connections with security limits and resource controls
 * Prevents connection exhaustion and implements rate limiting
 */
public class ConnectionManager {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionManager.class);
    
    // Connection limits
    private static final int MAX_CONCURRENT_CONNECTIONS = 10;
    private static final int CONNECTION_TIMEOUT_SECONDS = 30;
    private static final long RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
    private static final int MAX_CONNECTIONS_PER_WINDOW = 100;
    
    // Resource tracking
    private final Semaphore connectionSemaphore;
    private final AtomicInteger activeConnections;
    private final AtomicLong totalConnections;
    private final ConcurrentHashMap<String, ConnectionStats> clientStats;
    
    // Rate limiting
    private final AtomicLong windowStart;
    private final AtomicInteger connectionsInWindow;
    
    private final Config config;
    
    public ConnectionManager(Config config) {
        this.config = config;
        this.connectionSemaphore = new Semaphore(MAX_CONCURRENT_CONNECTIONS, true);
        this.activeConnections = new AtomicInteger(0);
        this.totalConnections = new AtomicLong(0);
        this.clientStats = new ConcurrentHashMap<>();
        this.windowStart = new AtomicLong(System.currentTimeMillis());
        this.connectionsInWindow = new AtomicInteger(0);
    }
    
    /**
     * Gets a managed database connection with security limits
     * @param clientId Identifier for the client requesting the connection
     * @return A managed database connection
     * @throws SQLException if connection fails or limits are exceeded
     */
    public ManagedConnection getConnection(String clientId) throws SQLException {
        // Rate limiting check
        checkRateLimit();
        
        // Client-specific rate limiting
        checkClientRateLimit(clientId);
        
        try {
            // Acquire connection permit with timeout
            if (!connectionSemaphore.tryAcquire(CONNECTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new SQLException("Connection timeout: Maximum concurrent connections reached");
            }
            
            // Create the actual database connection
            Connection rawConnection = config.newConnection();
            
            // Set connection properties for security
            configureConnection(rawConnection);
            
            // Track connection
            int active = activeConnections.incrementAndGet();
            long total = totalConnections.incrementAndGet();
            updateClientStats(clientId);
            connectionsInWindow.incrementAndGet();
            
            logger.info("Connection created - Active: {}, Total: {}, Client: {}", 
                       active, total, SecurityValidator.sanitizeForLogging(clientId));
            
            return new ManagedConnection(rawConnection, this, clientId);
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Connection request interrupted", e);
        } catch (Exception e) {
            // Release the permit if connection creation failed
            connectionSemaphore.release();
            throw new SQLException("Failed to create connection: " + e.getMessage(), e);
        }
    }
    
    /**
     * Configures connection with security settings
     * @param connection The database connection to configure
     * @throws SQLException if configuration fails
     */
    private void configureConnection(Connection connection) throws SQLException {
        // Set connection timeout
        if (connection.isValid(0)) {
            // Set read-only for additional security
            connection.setReadOnly(true);
            
            // Set transaction isolation level
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            
            // Disable auto-commit to prevent accidental commits
            connection.setAutoCommit(false);
        }
    }
    
    /**
     * Releases a managed connection and updates tracking
     * @param clientId The client that owned the connection
     */
    void releaseConnection(String clientId) {
        int active = activeConnections.decrementAndGet();
        connectionSemaphore.release();
        
        logger.debug("Connection released - Active: {}, Client: {}", 
                    active, SecurityValidator.sanitizeForLogging(clientId));
    }
    
    /**
     * Checks global rate limiting
     * @throws SQLException if rate limit is exceeded
     */
    private void checkRateLimit() throws SQLException {
        long now = System.currentTimeMillis();
        long currentWindowStart = windowStart.get();
        
        // Reset window if needed
        if (now - currentWindowStart > RATE_LIMIT_WINDOW_MS) {
            if (windowStart.compareAndSet(currentWindowStart, now)) {
                connectionsInWindow.set(0);
            }
        }
        
        // Check rate limit
        if (connectionsInWindow.get() >= MAX_CONNECTIONS_PER_WINDOW) {
            throw new SQLException("Rate limit exceeded: Too many connections in the current time window");
        }
    }
    
    /**
     * Checks client-specific rate limiting
     * @param clientId The client identifier
     * @throws SQLException if client rate limit is exceeded
     */
    private void checkClientRateLimit(String clientId) throws SQLException {
        if (clientId == null) {
            clientId = "unknown";
        }
        
        ConnectionStats stats = clientStats.computeIfAbsent(clientId, k -> new ConnectionStats());
        
        long now = System.currentTimeMillis();
        
        // Reset client window if needed
        if (now - stats.windowStart > RATE_LIMIT_WINDOW_MS) {
            synchronized (stats) {
                if (now - stats.windowStart > RATE_LIMIT_WINDOW_MS) {
                    stats.windowStart = now;
                    stats.connectionsInWindow = 0;
                }
            }
        }
        
        // Check client rate limit (lower than global)
        if (stats.connectionsInWindow >= MAX_CONNECTIONS_PER_WINDOW / 4) {
            throw new SQLException("Client rate limit exceeded for: " + SecurityValidator.sanitizeForLogging(clientId));
        }
    }
    
    /**
     * Updates client connection statistics
     * @param clientId The client identifier
     */
    private void updateClientStats(String clientId) {
        if (clientId == null) {
            clientId = "unknown";
        }
        
        ConnectionStats stats = clientStats.computeIfAbsent(clientId, k -> new ConnectionStats());
        stats.connectionsInWindow++;
        stats.totalConnections++;
    }
    
    /**
     * Gets current connection statistics
     * @return Connection statistics
     */
    public ConnectionStatistics getStatistics() {
        return new ConnectionStatistics(
            activeConnections.get(),
            totalConnections.get(),
            MAX_CONCURRENT_CONNECTIONS,
            connectionsInWindow.get()
        );
    }
    
    /**
     * Shuts down the connection manager and closes all connections
     */
    public void shutdown() {
        logger.info("Shutting down connection manager - Active connections: {}", activeConnections.get());
        
        // Wait for active connections to close (with timeout)
        try {
            boolean acquired = connectionSemaphore.tryAcquire(MAX_CONCURRENT_CONNECTIONS, 30, TimeUnit.SECONDS);
            if (!acquired) {
                logger.warn("Timeout waiting for connections to close during shutdown");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted while waiting for connections to close");
        }
        
        logger.info("Connection manager shutdown complete");
    }
    
    /**
     * Internal class to track per-client connection statistics
     */
    private static class ConnectionStats {
        volatile long windowStart = System.currentTimeMillis();
        volatile int connectionsInWindow = 0;
        volatile long totalConnections = 0;
    }
    
    /**
     * Public statistics class
     */
    public static class ConnectionStatistics {
        public final int activeConnections;
        public final long totalConnections;
        public final int maxConnections;
        public final int connectionsInCurrentWindow;
        
        public ConnectionStatistics(int active, long total, int max, int inWindow) {
            this.activeConnections = active;
            this.totalConnections = total;
            this.maxConnections = max;
            this.connectionsInCurrentWindow = inWindow;
        }
        
        @Override
        public String toString() {
            return String.format("Connections[active=%d, total=%d, max=%d, window=%d]", 
                               activeConnections, totalConnections, maxConnections, connectionsInCurrentWindow);
        }
    }
}