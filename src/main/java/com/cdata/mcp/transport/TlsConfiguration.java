package com.cdata.mcp.transport;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;

/**
 * Configuration for TLS/SSL transport security
 * Handles certificate management, cipher suites, and security protocols
 */
public class TlsConfiguration {
    
    // Security defaults
    private static final List<String> DEFAULT_PROTOCOLS = Arrays.asList("TLSv1.3", "TLSv1.2");
    private static final List<String> SECURE_CIPHER_SUITES = Arrays.asList(
        // TLS 1.3 ciphers
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        // TLS 1.2 ciphers (secure fallback)
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    );
    
    // Configuration properties
    private boolean tlsEnabled = false;
    private int httpsPort = 8443;
    private String keystorePath;
    private String keystorePassword;
    private String keystoreType = "PKCS12";
    private String truststorePath;
    private String truststorePassword;
    private String truststoreType = "PKCS12";
    
    // Client certificate settings
    private boolean clientAuthRequired = false;
    private boolean clientAuthWanted = false;
    
    // Protocol and cipher settings
    private List<String> enabledProtocols = DEFAULT_PROTOCOLS;
    private List<String> enabledCipherSuites = SECURE_CIPHER_SUITES;
    
    // Security headers
    private boolean enableSecurityHeaders = true;
    private boolean enableHsts = true;
    private int hstsMaxAge = 31536000; // 1 year
    
    /**
     * Creates a default TLS configuration (disabled)
     */
    public TlsConfiguration() {
    }
    
    /**
     * Creates a TLS configuration with basic settings
     * @param keystorePath Path to the keystore file
     * @param keystorePassword Password for the keystore
     */
    public TlsConfiguration(String keystorePath, String keystorePassword) {
        this.tlsEnabled = true;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
    }
    
    /**
     * Validates the TLS configuration
     * @throws TlsConfigurationException if configuration is invalid
     */
    public void validate() throws TlsConfigurationException {
        if (!tlsEnabled) {
            return; // No validation needed if TLS is disabled
        }
        
        // Validate keystore
        if (keystorePath == null || keystorePath.trim().isEmpty()) {
            throw new TlsConfigurationException("Keystore path is required when TLS is enabled");
        }
        
        Path keystore = Paths.get(keystorePath);
        if (!Files.exists(keystore)) {
            throw new TlsConfigurationException("Keystore file not found: " + keystorePath);
        }
        
        if (!Files.isRegularFile(keystore)) {
            throw new TlsConfigurationException("Keystore path is not a file: " + keystorePath);
        }
        
        if (keystorePassword == null || keystorePassword.trim().isEmpty()) {
            throw new TlsConfigurationException("Keystore password is required");
        }
        
        // Validate truststore if specified
        if (truststorePath != null && !truststorePath.trim().isEmpty()) {
            Path truststore = Paths.get(truststorePath);
            if (!Files.exists(truststore)) {
                throw new TlsConfigurationException("Truststore file not found: " + truststorePath);
            }
            
            if (!Files.isRegularFile(truststore)) {
                throw new TlsConfigurationException("Truststore path is not a file: " + truststorePath);
            }
        }
        
        // Validate port
        if (httpsPort < 1 || httpsPort > 65535) {
            throw new TlsConfigurationException("Invalid HTTPS port: " + httpsPort);
        }
        
        // Validate client auth settings
        if (clientAuthRequired && clientAuthWanted) {
            throw new TlsConfigurationException("Cannot have both client auth required and wanted");
        }
        
        if ((clientAuthRequired || clientAuthWanted) && 
            (truststorePath == null || truststorePath.trim().isEmpty())) {
            throw new TlsConfigurationException("Truststore is required for client authentication");
        }
        
        // Validate protocols
        if (enabledProtocols == null || enabledProtocols.isEmpty()) {
            throw new TlsConfigurationException("At least one TLS protocol must be enabled");
        }
        
        // Validate cipher suites
        if (enabledCipherSuites == null || enabledCipherSuites.isEmpty()) {
            throw new TlsConfigurationException("At least one cipher suite must be enabled");
        }
    }
    
    // Getters and setters
    
    public boolean isTlsEnabled() {
        return tlsEnabled;
    }
    
    public void setTlsEnabled(boolean tlsEnabled) {
        this.tlsEnabled = tlsEnabled;
    }
    
    public int getHttpsPort() {
        return httpsPort;
    }
    
    public void setHttpsPort(int httpsPort) {
        this.httpsPort = httpsPort;
    }
    
    public String getKeystorePath() {
        return keystorePath;
    }
    
    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }
    
    public String getKeystorePassword() {
        return keystorePassword;
    }
    
    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }
    
    public String getKeystoreType() {
        return keystoreType;
    }
    
    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }
    
    public String getTruststorePath() {
        return truststorePath;
    }
    
    public void setTruststorePath(String truststorePath) {
        this.truststorePath = truststorePath;
    }
    
    public String getTruststorePassword() {
        return truststorePassword;
    }
    
    public void setTruststorePassword(String truststorePassword) {
        this.truststorePassword = truststorePassword;
    }
    
    public String getTruststoreType() {
        return truststoreType;
    }
    
    public void setTruststoreType(String truststoreType) {
        this.truststoreType = truststoreType;
    }
    
    public boolean isClientAuthRequired() {
        return clientAuthRequired;
    }
    
    public void setClientAuthRequired(boolean clientAuthRequired) {
        this.clientAuthRequired = clientAuthRequired;
    }
    
    public boolean isClientAuthWanted() {
        return clientAuthWanted;
    }
    
    public void setClientAuthWanted(boolean clientAuthWanted) {
        this.clientAuthWanted = clientAuthWanted;
    }
    
    public List<String> getEnabledProtocols() {
        return enabledProtocols;
    }
    
    public void setEnabledProtocols(List<String> enabledProtocols) {
        this.enabledProtocols = enabledProtocols;
    }
    
    public List<String> getEnabledCipherSuites() {
        return enabledCipherSuites;
    }
    
    public void setEnabledCipherSuites(List<String> enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
    }
    
    public boolean isEnableSecurityHeaders() {
        return enableSecurityHeaders;
    }
    
    public void setEnableSecurityHeaders(boolean enableSecurityHeaders) {
        this.enableSecurityHeaders = enableSecurityHeaders;
    }
    
    public boolean isEnableHsts() {
        return enableHsts;
    }
    
    public void setEnableHsts(boolean enableHsts) {
        this.enableHsts = enableHsts;
    }
    
    public int getHstsMaxAge() {
        return hstsMaxAge;
    }
    
    public void setHstsMaxAge(int hstsMaxAge) {
        this.hstsMaxAge = hstsMaxAge;
    }
    
    @Override
    public String toString() {
        return String.format("TlsConfiguration[enabled=%s, port=%d, keystore=%s, clientAuth=%s/%s]",
                           tlsEnabled, httpsPort, 
                           keystorePath != null ? new File(keystorePath).getName() : "none",
                           clientAuthRequired ? "required" : "none",
                           clientAuthWanted ? "wanted" : "none");
    }
}