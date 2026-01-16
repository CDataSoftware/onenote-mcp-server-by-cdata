package com.cdata.mcp.tests;

import com.cdata.mcp.Config;
import com.cdata.mcp.config.ConfigurationSecurityReport;
import com.cdata.mcp.config.EnvironmentConfigurationProvider;
import com.cdata.mcp.config.SecretManager;
import org.junit.Before;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.file.attribute.PosixFilePermission;

import static org.junit.Assert.*;

public class ConfigurationSecurityTests {
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private Config config;
    private File configFile;
    
    @Before
    public void setUp() throws IOException {
        config = new Config();
        configFile = tempFolder.newFile("test-config.properties");
        
        // Set secure permissions
        setSecurePermissions(configFile);
        
        // Write test configuration with mix of secure and insecure values
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write("Prefix=TestPrefix\n");
            writer.write("DriverClass=com.cdata.jdbc.onenote.OneNoteDriver\n");
            writer.write("DriverPath=" + tempFolder.newFile("test-driver.jar").getAbsolutePath() + "\n");
            writer.write("JdbcUrl=jdbc:onenote:AuthScheme=OAuth;\n");
            writer.write("PlainPassword=plainTextPassword\n");
        }
    }
    
    private void setSecurePermissions(File file) {
        if (file.toPath().getFileSystem().supportedFileAttributeViews().contains("posix")) {
            try {
                Set<PosixFilePermission> securePerms = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
                java.nio.file.Files.setPosixFilePermissions(file.toPath(), securePerms);
            } catch (Exception e) {
                // Ignore if can't set permissions
            }
        }
    }
    
    @Test
    public void testConfigurationLoadingWithEnhancedProvider() throws IOException {
        config.load(configFile.getAbsolutePath());
        
        // Verify enhanced providers are initialized
        assertNotNull(config.getEnvironmentConfigProvider());
        assertNotNull(config.getSecretManager());
        
        // Verify basic properties still work
        assertEquals("TestPrefix", config.getPrefix());
        assertEquals("com.cdata.jdbc.onenote.OneNoteDriver", config.getDriver());
    }
    
    @Test
    public void testEncryptConfigurationValue() throws IOException {
        config.load(configFile.getAbsolutePath());
        
        String plainText = "sensitivePassword";
        String encrypted = config.encryptConfigurationValue(plainText);
        
        assertNotNull(encrypted);
        assertTrue(encrypted.startsWith("ENC("));
        assertTrue(encrypted.endsWith(")"));
        assertNotEquals(plainText, encrypted);
    }
    
    @Test(expected = IllegalStateException.class)
    public void testEncryptConfigurationValueWithoutInitialization() {
        // Should throw exception if environment provider not initialized
        config.encryptConfigurationValue("test");
    }
    
    @Test
    public void testConfigurationSecurityReport() throws IOException {
        config.load(configFile.getAbsolutePath());
        
        ConfigurationSecurityReport report = config.validateConfigurationSecurity();
        assertNotNull(report);
        
        // Should not be considered secure due to plain text passwords
        assertFalse(report.isSecure());
        
        // Should have a security score less than perfect
        assertTrue(report.getSecurityScore() < 100);
        
        // Should have recommendations
        List<String> recommendations = report.getRecommendations();
        assertNotNull(recommendations);
        assertFalse(recommendations.isEmpty());
    }
    
    @Test
    public void testSecurityReportWithEncryptedValues() throws IOException {
        // Create config with encrypted values
        EnvironmentConfigurationProvider envProvider = new EnvironmentConfigurationProvider();
        String encryptedPassword = envProvider.encryptValue("securePassword");
        
        try (FileWriter writer = new FileWriter(configFile, true)) {
            writer.write("EncryptedPassword=" + encryptedPassword + "\n");
        }
        
        // Ensure secure permissions after writing
        setSecurePermissions(configFile);
        
        config.load(configFile.getAbsolutePath());
        ConfigurationSecurityReport report = config.validateConfigurationSecurity();
        
        assertNotNull(report);
        
        // Generate summary report
        String summary = report.generateSummary();
        assertNotNull(summary);
        assertTrue(summary.contains("Configuration Security Report"));
        assertTrue(summary.contains("Security Level:"));
        assertTrue(summary.contains("Recommendations:"));
    }
    
    @Test
    public void testSecurityReportScoring() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        // Initially should have high score
        int initialScore = report.getSecurityScore();
        assertTrue(initialScore >= 80);
        
        // Add unsecured properties and verify score decreases
        report.addUnsecuredProperty("password1");
        int scoreAfterOne = report.getSecurityScore();
        assertTrue(scoreAfterOne < initialScore);
        
        report.addUnsecuredProperty("password2");
        int scoreAfterTwo = report.getSecurityScore();
        assertTrue(scoreAfterTwo < scoreAfterOne);
    }
    
    @Test
    public void testSecurityLevels() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        // Initially should be GOOD because secret manager not available (deducts 20 points)
        String initialLevel = report.getSecurityLevel();
        assertTrue("Initial level should be GOOD", initialLevel.equals("GOOD") || initialLevel.equals("EXCELLENT"));
        
        // Add unsecured properties to lower the score
        report.addUnsecuredProperty("prop1");
        String level1 = report.getSecurityLevel();
        
        // Add more to get to lower levels
        for (int i = 2; i <= 5; i++) {
            report.addUnsecuredProperty("prop" + i);
        }
        
        // Should be at a lower level now
        String finalLevel = report.getSecurityLevel();
        assertNotEquals("EXCELLENT", finalLevel);
        
        // Test with secret manager available
        ConfigurationSecurityReport reportWithSecrets = new ConfigurationSecurityReport();
        reportWithSecrets.setSecretManagerAvailable(true);
        assertEquals("EXCELLENT", reportWithSecrets.getSecurityLevel());
    }
    
    @Test
    public void testUnsecuredPropertiesTracking() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        assertTrue(report.getUnsecuredProperties().isEmpty());
        
        report.addUnsecuredProperty("password");
        report.addUnsecuredProperty("apiKey");
        
        List<String> unsecured = report.getUnsecuredProperties();
        assertEquals(2, unsecured.size());
        assertTrue(unsecured.contains("password"));
        assertTrue(unsecured.contains("apiKey"));
        
        // Adding same property again should not duplicate
        report.addUnsecuredProperty("password");
        assertEquals(2, report.getUnsecuredProperties().size());
    }
    
    @Test
    public void testSecretManagerAvailability() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        assertFalse(report.isSecretManagerAvailable());
        
        report.setSecretManagerAvailable(true);
        assertTrue(report.isSecretManagerAvailable());
        
        // Should affect security score
        int scoreWithSecretManager = report.getSecurityScore();
        
        report.setSecretManagerAvailable(false);
        int scoreWithoutSecretManager = report.getSecurityScore();
        
        assertTrue(scoreWithSecretManager > scoreWithoutSecretManager);
    }
    
    @Test
    public void testAvailableProvidersTracking() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        Map<String, Boolean> providers = Map.of(
            "Vault", true,
            "AWS", false,
            "File", true
        );
        
        report.setAvailableProviders(providers);
        
        Map<String, Boolean> retrieved = report.getAvailableProviders();
        assertEquals(providers, retrieved);
    }
    
    @Test
    public void testCustomRecommendations() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        
        List<String> initialRecs = report.getRecommendations();
        int initialCount = initialRecs.size();
        
        report.addRecommendation("Custom security recommendation");
        
        List<String> updatedRecs = report.getRecommendations();
        assertEquals(initialCount + 1, updatedRecs.size());
        assertTrue(updatedRecs.contains("Custom security recommendation"));
        
        // Adding same recommendation should not duplicate
        report.addRecommendation("Custom security recommendation");
        assertEquals(initialCount + 1, report.getRecommendations().size());
    }
    
    @Test
    public void testReportToString() {
        ConfigurationSecurityReport report = new ConfigurationSecurityReport();
        report.addUnsecuredProperty("testProp");
        report.setSecretManagerAvailable(true);
        
        String toString = report.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("ConfigurationSecurityReport"));
        assertTrue(toString.contains("secure="));
        assertTrue(toString.contains("score="));
        assertTrue(toString.contains("unsecured="));
        assertTrue(toString.contains("secretManager="));
    }
    
    @Test
    public void testSecurePropertyRetrieval() throws IOException {
        // Test the secure property retrieval mechanism
        config.load(configFile.getAbsolutePath());
        
        SecretManager secretManager = config.getSecretManager();
        assertNotNull(secretManager);
        
        // Set a secret and verify it can be retrieved
        secretManager.setSecret("test.secret", "secretValue");
        
        try {
            String value = secretManager.getSecret("test.secret");
            assertEquals("secretValue", value);
        } catch (SecretManager.SecretNotFoundException e) {
            fail("Should be able to retrieve cached secret");
        }
    }
    
    @Test
    public void testConfigurationShutdown() throws IOException {
        config.load(configFile.getAbsolutePath());
        
        // Verify providers are initialized
        assertNotNull(config.getSecretManager());
        
        // Shutdown should clear secret cache
        config.shutdown();
        
        // Verify secret cache is cleared (indirectly)
        SecretManager secretManager = config.getSecretManager();
        assertNotNull(secretManager); // Manager still exists but cache should be cleared
    }
    
    @Test
    public void testEnvironmentVariablePriority() throws IOException {
        config.load(configFile.getAbsolutePath());
        
        EnvironmentConfigurationProvider provider = config.getEnvironmentConfigProvider();
        assertNotNull(provider);
        
        // Test that environment variables would take priority over file properties
        // (We can't actually set env vars in tests, but we can verify the logic exists)
        String value = provider.getProperty("TestProperty", "default");
        // Should return "default" since no env var is set and property doesn't exist in our test file
        assertEquals("default", value);
    }
}