package com.cdata.mcp.tests;

import com.cdata.mcp.transport.TlsConfiguration;
import com.cdata.mcp.transport.TlsConfigurationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.*;

public class TlsConfigurationTests {
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private TlsConfiguration tlsConfig;
    private File testKeystore;
    private File testTruststore;
    
    @Before
    public void setUp() throws IOException {
        tlsConfig = new TlsConfiguration();
        
        // Create temporary keystore and truststore files for testing
        testKeystore = tempFolder.newFile("test-keystore.p12");
        testTruststore = tempFolder.newFile("test-truststore.p12");
        
        // Write some dummy content to make them exist
        java.nio.file.Files.write(testKeystore.toPath(), "dummy keystore content".getBytes());
        java.nio.file.Files.write(testTruststore.toPath(), "dummy truststore content".getBytes());
    }
    
    @Test
    public void testDefaultConfiguration() throws TlsConfigurationException {
        // Default configuration should be valid (TLS disabled)
        tlsConfig.validate();
        
        assertFalse("TLS should be disabled by default", tlsConfig.isTlsEnabled());
        assertEquals("Default HTTPS port should be 8443", 8443, tlsConfig.getHttpsPort());
        assertEquals("Default keystore type should be PKCS12", "PKCS12", tlsConfig.getKeystoreType());
        assertEquals("Default truststore type should be PKCS12", "PKCS12", tlsConfig.getTruststoreType());
        assertFalse("Client auth should not be required by default", tlsConfig.isClientAuthRequired());
        assertFalse("Client auth should not be wanted by default", tlsConfig.isClientAuthWanted());
        assertTrue("Security headers should be enabled by default", tlsConfig.isEnableSecurityHeaders());
        assertTrue("HSTS should be enabled by default", tlsConfig.isEnableHsts());
    }
    
    @Test
    public void testValidTlsConfiguration() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        
        tlsConfig.validate();
        
        assertTrue("TLS should be enabled", tlsConfig.isTlsEnabled());
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testMissingKeystorePath() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePassword("password123");
        
        tlsConfig.validate();
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testMissingKeystorePassword() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        
        tlsConfig.validate();
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testNonExistentKeystore() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath("/non/existent/keystore.p12");
        tlsConfig.setKeystorePassword("password123");
        
        tlsConfig.validate();
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testInvalidPort() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setHttpsPort(70000); // Invalid port
        
        tlsConfig.validate();
    }
    
    @Test
    public void testValidTruststoreConfiguration() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setTruststorePath(testTruststore.getAbsolutePath());
        tlsConfig.setTruststorePassword("trustpass");
        
        tlsConfig.validate();
        
        assertEquals("Truststore path should be set", testTruststore.getAbsolutePath(), tlsConfig.getTruststorePath());
        assertEquals("Truststore password should be set", "trustpass", tlsConfig.getTruststorePassword());
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testNonExistentTruststore() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setTruststorePath("/non/existent/truststore.p12");
        tlsConfig.setTruststorePassword("trustpass");
        
        tlsConfig.validate();
    }
    
    @Test
    public void testClientAuthenticationConfiguration() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setTruststorePath(testTruststore.getAbsolutePath());
        tlsConfig.setTruststorePassword("trustpass");
        tlsConfig.setClientAuthRequired(true);
        
        tlsConfig.validate();
        
        assertTrue("Client auth should be required", tlsConfig.isClientAuthRequired());
        assertFalse("Client auth wanted should be false when required is true", tlsConfig.isClientAuthWanted());
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testClientAuthWithoutTruststore() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setClientAuthRequired(true); // Without truststore
        
        tlsConfig.validate();
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testConflictingClientAuthSettings() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setTruststorePath(testTruststore.getAbsolutePath());
        tlsConfig.setTruststorePassword("trustpass");
        tlsConfig.setClientAuthRequired(true);
        tlsConfig.setClientAuthWanted(true); // Both cannot be true
        
        tlsConfig.validate();
    }
    
    @Test
    public void testProtocolConfiguration() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setEnabledProtocols(Arrays.asList("TLSv1.3", "TLSv1.2"));
        
        tlsConfig.validate();
        
        assertEquals("Should have 2 enabled protocols", 2, tlsConfig.getEnabledProtocols().size());
        assertTrue("Should include TLSv1.3", tlsConfig.getEnabledProtocols().contains("TLSv1.3"));
        assertTrue("Should include TLSv1.2", tlsConfig.getEnabledProtocols().contains("TLSv1.2"));
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testEmptyProtocolList() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setEnabledProtocols(Arrays.asList()); // Empty list
        
        tlsConfig.validate();
    }
    
    @Test
    public void testCipherSuiteConfiguration() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setEnabledCipherSuites(Arrays.asList("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"));
        
        tlsConfig.validate();
        
        assertEquals("Should have 2 enabled cipher suites", 2, tlsConfig.getEnabledCipherSuites().size());
        assertTrue("Should include TLS_AES_256_GCM_SHA384", 
                  tlsConfig.getEnabledCipherSuites().contains("TLS_AES_256_GCM_SHA384"));
    }
    
    @Test(expected = TlsConfigurationException.class)
    public void testEmptyCipherSuiteList() throws TlsConfigurationException {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setKeystorePassword("password123");
        tlsConfig.setEnabledCipherSuites(Arrays.asList()); // Empty list
        
        tlsConfig.validate();
    }
    
    @Test
    public void testSecurityHeaderConfiguration() {
        tlsConfig.setEnableSecurityHeaders(false);
        tlsConfig.setEnableHsts(false);
        tlsConfig.setHstsMaxAge(86400);
        
        assertFalse("Security headers should be disabled", tlsConfig.isEnableSecurityHeaders());
        assertFalse("HSTS should be disabled", tlsConfig.isEnableHsts());
        assertEquals("HSTS max age should be set", 86400, tlsConfig.getHstsMaxAge());
    }
    
    @Test
    public void testToString() {
        tlsConfig.setTlsEnabled(true);
        tlsConfig.setHttpsPort(9443);
        tlsConfig.setKeystorePath(testKeystore.getAbsolutePath());
        tlsConfig.setClientAuthRequired(true);
        
        String str = tlsConfig.toString();
        
        assertTrue("Should contain enabled=true", str.contains("enabled=true"));
        assertTrue("Should contain port=9443", str.contains("port=9443"));
        assertTrue("Should contain keystore filename", str.contains("test-keystore.p12"));
        assertTrue("Should contain client auth info", str.contains("required"));
    }
    
    @Test
    public void testConstructorWithBasicSettings() throws TlsConfigurationException {
        TlsConfiguration config = new TlsConfiguration(testKeystore.getAbsolutePath(), "password123");
        
        config.validate();
        
        assertTrue("TLS should be enabled", config.isTlsEnabled());
        assertEquals("Keystore path should be set", testKeystore.getAbsolutePath(), config.getKeystorePath());
        assertEquals("Keystore password should be set", "password123", config.getKeystorePassword());
    }
}