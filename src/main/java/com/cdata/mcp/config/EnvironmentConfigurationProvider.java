package com.cdata.mcp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

/**
 * Provides secure configuration management with environment variable support,
 * encrypted configuration values, and proper file permission validation.
 */
public class EnvironmentConfigurationProvider {
    private static final Logger logger = LoggerFactory.getLogger(EnvironmentConfigurationProvider.class);
    
    private static final String CONFIG_ENCRYPTION_KEY_ENV = "MCP_CONFIG_ENCRYPTION_KEY";
    private static final String CONFIG_FILE_ENV = "MCP_CONFIG_FILE";
    private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
    private static final String ENCRYPTED_VALUE_SUFFIX = ")";
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    
    private final Properties properties;
    private final SecretKey encryptionKey;
    private final SecureRandom secureRandom;
    
    public EnvironmentConfigurationProvider() {
        this.properties = new Properties();
        this.encryptionKey = initializeEncryptionKey();
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Loads configuration from file with security validation
     * @param configPath Path to configuration file
     * @throws IOException if file cannot be read or has insecure permissions
     * @throws SecurityException if file permissions are too permissive
     */
    public void loadConfiguration(String configPath) throws IOException, SecurityException {
        // Check for environment override
        String envConfigPath = System.getenv(CONFIG_FILE_ENV);
        if (envConfigPath != null && !envConfigPath.trim().isEmpty()) {
            configPath = envConfigPath;
            logger.info("Using configuration file from environment: {}", configPath);
        }
        
        Path path = Paths.get(configPath);
        
        // Validate file exists and permissions
        try {
            validateConfigurationFile(path);
        } catch (SecurityException e) {
            throw new IOException("Security validation failed: " + e.getMessage(), e);
        }
        
        // Load properties
        try (FileInputStream fis = new FileInputStream(configPath)) {
            properties.load(fis);
            logger.info("Configuration loaded from: {}", configPath);
        }
    }
    
    /**
     * Gets a configuration property with environment variable and encryption support
     * @param key The property key
     * @param defaultValue Default value if property not found
     * @return The property value (decrypted if necessary)
     */
    public String getProperty(String key, String defaultValue) {
        // 1. Check environment variable first (highest priority)
        String envKey = convertToEnvironmentKey(key);
        String envValue = System.getenv(envKey);
        if (envValue != null && !envValue.trim().isEmpty()) {
            logger.debug("Using environment value for key: {}", key);
            return decryptIfNeeded(envValue);
        }
        
        // 2. Check properties file
        String propValue = properties.getProperty(key);
        if (propValue != null && !propValue.trim().isEmpty()) {
            return decryptIfNeeded(propValue);
        }
        
        // 3. Return default value
        return defaultValue;
    }
    
    /**
     * Gets a configuration property (required)
     * @param key The property key
     * @return The property value (decrypted if necessary)
     * @throws IllegalArgumentException if property is not found
     */
    public String getRequiredProperty(String key) {
        String value = getProperty(key, null);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Required configuration property not found: " + key);
        }
        return value;
    }
    
    /**
     * Gets a boolean configuration property
     * @param key The property key
     * @param defaultValue Default value if property not found
     * @return The boolean value
     */
    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = getProperty(key, String.valueOf(defaultValue));
        return Boolean.parseBoolean(value);
    }
    
    /**
     * Gets an integer configuration property
     * @param key The property key
     * @param defaultValue Default value if property not found
     * @return The integer value
     */
    public int getIntProperty(String key, int defaultValue) {
        String value = getProperty(key, String.valueOf(defaultValue));
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            logger.warn("Invalid integer value for property {}: {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }
    
    /**
     * Gets a long configuration property
     * @param key The property key
     * @param defaultValue Default value if property not found
     * @return The long value
     */
    public long getLongProperty(String key, long defaultValue) {
        String value = getProperty(key, String.valueOf(defaultValue));
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            logger.warn("Invalid long value for property {}: {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }
    
    /**
     * Encrypts a configuration value
     * @param plainText The plain text value
     * @return Encrypted value with ENC() wrapper
     */
    public String encryptValue(String plainText) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            
            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, parameterSpec);
            
            byte[] encryptedData = cipher.doFinal(plainText.getBytes());
            
            // Combine IV and encrypted data
            byte[] encryptedWithIv = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
            System.arraycopy(encryptedData, 0, encryptedWithIv, iv.length, encryptedData.length);
            
            String base64Encrypted = Base64.getEncoder().encodeToString(encryptedWithIv);
            return ENCRYPTED_VALUE_PREFIX + base64Encrypted + ENCRYPTED_VALUE_SUFFIX;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt configuration value", e);
        }
    }
    
    /**
     * Checks if a value is encrypted
     * @param value The value to check
     * @return true if the value is encrypted
     */
    public boolean isEncrypted(String value) {
        return value != null && 
               value.startsWith(ENCRYPTED_VALUE_PREFIX) && 
               value.endsWith(ENCRYPTED_VALUE_SUFFIX);
    }
    
    /**
     * Validates configuration file permissions
     * @param configPath Path to configuration file
     * @throws SecurityException if permissions are too permissive
     */
    private void validateConfigurationFile(Path configPath) throws SecurityException, IOException {
        if (!Files.exists(configPath)) {
            throw new IOException("Configuration file not found: " + configPath);
        }
        
        // Check file permissions on Unix-like systems
        if (configPath.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(configPath);
                
                // Configuration files should not be world-readable or group-writable
                if (permissions.contains(PosixFilePermission.OTHERS_READ) || 
                    permissions.contains(PosixFilePermission.OTHERS_WRITE) ||
                    permissions.contains(PosixFilePermission.GROUP_WRITE)) {
                    
                    throw new SecurityException(
                        "Configuration file has insecure permissions: " + configPath + ". " +
                        "File should not be readable by others or writable by group. " +
                        "Recommended permissions: 600 (rw-------) or 640 (rw-r-----)"
                    );
                }
                
                logger.debug("Configuration file permissions validated: {}", configPath);
                
            } catch (UnsupportedOperationException e) {
                logger.warn("Cannot validate POSIX permissions on this filesystem: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Converts a property key to environment variable format
     * @param key The property key
     * @return Environment variable key
     */
    private String convertToEnvironmentKey(String key) {
        return "MCP_" + key.toUpperCase()
                           .replace(".", "_")
                           .replace("-", "_");
    }
    
    /**
     * Decrypts a value if it's encrypted
     * @param value The potentially encrypted value
     * @return Decrypted value or original value if not encrypted
     */
    private String decryptIfNeeded(String value) {
        if (!isEncrypted(value)) {
            return value;
        }
        
        try {
            // Extract encrypted content
            String encryptedContent = value.substring(
                ENCRYPTED_VALUE_PREFIX.length(), 
                value.length() - ENCRYPTED_VALUE_SUFFIX.length()
            );
            
            byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedContent);
            
            // Extract IV and encrypted data
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
            
            System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
            System.arraycopy(encryptedWithIv, iv.length, encryptedData, 0, encryptedData.length);
            
            // Decrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, parameterSpec);
            
            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt configuration value", e);
        }
    }
    
    /**
     * Initializes the encryption key from environment or generates a new one
     * @return The encryption key
     */
    private SecretKey initializeEncryptionKey() {
        String keyBase64 = System.getenv(CONFIG_ENCRYPTION_KEY_ENV);
        
        if (keyBase64 != null && !keyBase64.trim().isEmpty()) {
            try {
                byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
                return new SecretKeySpec(keyBytes, "AES");
            } catch (Exception e) {
                logger.warn("Invalid encryption key in environment variable, generating new key");
            }
        }
        
        // Generate new key if not provided or invalid
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey key = keyGenerator.generateKey();
            
            // Log the key for first-time setup (should be stored securely)
            String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
            logger.warn("Generated new encryption key. Set environment variable {}={}", 
                       CONFIG_ENCRYPTION_KEY_ENV, keyString);
            logger.warn("Store this key securely and remove from logs!");
            
            return key;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize encryption key", e);
        }
    }
    
    /**
     * Gets all property keys (for debugging/validation)
     * @return Set of property keys
     */
    public Set<String> getPropertyKeys() {
        return properties.stringPropertyNames();
    }
    
    /**
     * Clears all properties (for testing)
     */
    public void clear() {
        properties.clear();
    }
}