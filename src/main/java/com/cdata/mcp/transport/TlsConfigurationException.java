package com.cdata.mcp.transport;

/**
 * Exception thrown when TLS configuration is invalid
 */
public class TlsConfigurationException extends Exception {
    
    public TlsConfigurationException(String message) {
        super(message);
    }
    
    public TlsConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}