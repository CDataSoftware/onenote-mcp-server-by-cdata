package com.cdata.mcp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

/**
 * Security validation utilities for the MCP server
 * Provides JAR verification, driver allowlisting, and path validation
 */
public class SecurityValidator {
    
    // Allowlisted JDBC driver classes - only these are permitted
    private static final Set<String> ALLOWED_DRIVER_CLASSES = new HashSet<>(Arrays.asList(
        "cdata.jdbc.onenote.OneNoteDriver",
        "cdata.jdbc.salesforce.SalesforceDriver",
        "cdata.jdbc.sharepoint.SharePointDriver",
        "cdata.jdbc.excel.ExcelDriver",
        "cdata.jdbc.googledrive.GoogleDriveDriver"
        // Add other trusted CData drivers as needed
    ));
    
    // Allowed file extensions for driver JARs
    private static final Set<String> ALLOWED_JAR_EXTENSIONS = new HashSet<>(Arrays.asList(".jar"));
    
    // Maximum allowed JAR file size (50MB)
    private static final long MAX_JAR_SIZE = 50 * 1024 * 1024;
    
    /**
     * Validates that a driver class name is in the allowlist
     * @param driverClassName The fully qualified driver class name
     * @throws SecurityException if the driver is not allowlisted
     */
    public static void validateDriverClass(String driverClassName) throws SecurityException {
        if (driverClassName == null || driverClassName.trim().isEmpty()) {
            throw new SecurityException("Driver class name cannot be null or empty");
        }
        
        if (!ALLOWED_DRIVER_CLASSES.contains(driverClassName)) {
            throw new SecurityException("Driver class not in allowlist: " + driverClassName);
        }
    }
    
    /**
     * Validates JAR file security including path, size, and basic integrity
     * @param jarPath Path to the JAR file
     * @throws SecurityException if the JAR file fails security validation
     */
    public static void validateJarFile(String jarPath) throws SecurityException {
        if (jarPath == null || jarPath.trim().isEmpty()) {
            throw new SecurityException("JAR path cannot be null or empty");
        }
        
        File jarFile = new File(jarPath);
        
        // Validate file exists
        if (!jarFile.exists()) {
            throw new SecurityException("JAR file does not exist: " + jarPath);
        }
        
        // Validate it's a regular file
        if (!jarFile.isFile()) {
            throw new SecurityException("JAR path is not a regular file: " + jarPath);
        }
        
        // Validate file extension
        String fileName = jarFile.getName().toLowerCase();
        boolean validExtension = ALLOWED_JAR_EXTENSIONS.stream()
            .anyMatch(ext -> fileName.endsWith(ext));
        if (!validExtension) {
            throw new SecurityException("Invalid JAR file extension: " + fileName);
        }
        
        // Validate file size
        if (jarFile.length() > MAX_JAR_SIZE) {
            throw new SecurityException("JAR file exceeds maximum allowed size: " + jarFile.length());
        }
        
        // Validate against path traversal
        validatePath(jarPath);
        
        // Validate JAR integrity
        validateJarIntegrity(jarFile);
    }
    
    /**
     * Validates path to prevent path traversal attacks
     * @param path The file path to validate
     * @throws SecurityException if path contains dangerous elements
     */
    public static void validatePath(String path) throws SecurityException {
        if (path == null) {
            throw new SecurityException("Path cannot be null");
        }
        
        // Normalize the path
        Path normalizedPath = Paths.get(path).normalize().toAbsolutePath();
        String pathStr = normalizedPath.toString();
        
        // Check for path traversal attempts
        if (pathStr.contains("..") || pathStr.contains("~")) {
            throw new SecurityException("Path traversal attempt detected: " + path);
        }
        
        // Ensure path doesn't access system directories
        String[] forbiddenPaths = {
            "/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/root/",
            "C:\\Windows\\", "C:\\Program Files\\", "C:\\Users\\Administrator\\"
        };
        
        for (String forbidden : forbiddenPaths) {
            if (pathStr.startsWith(forbidden)) {
                throw new SecurityException("Access to system directory not allowed: " + path);
            }
        }
    }
    
    /**
     * Validates JAR file integrity by checking it can be opened and has valid structure
     * @param jarFile The JAR file to validate
     * @throws SecurityException if JAR is corrupted or malformed
     */
    private static void validateJarIntegrity(File jarFile) throws SecurityException {
        try (JarFile jar = new JarFile(jarFile, true)) {
            // Check if JAR has a manifest
            Manifest manifest = jar.getManifest();
            if (manifest == null) {
                throw new SecurityException("JAR file has no manifest: " + jarFile.getName());
            }
            
            // Validate JAR entries (basic check for malformed entries)
            var entries = jar.entries();
            int entryCount = 0;
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                entryCount++;
                
                // Prevent zip bombs
                if (entryCount > 10000) {
                    throw new SecurityException("JAR contains too many entries (potential zip bomb)");
                }
                
                // Validate entry names
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/")) {
                    throw new SecurityException("JAR contains dangerous entry path: " + entryName);
                }
                
                // Check for excessively large entries
                if (entry.getSize() > 100 * 1024 * 1024) { // 100MB max per entry
                    throw new SecurityException("JAR entry too large: " + entryName);
                }
            }
            
        } catch (IOException e) {
            throw new SecurityException("Failed to validate JAR integrity: " + e.getMessage());
        }
    }
    
    /**
     * Validates log file path for security
     * @param logPath The log file path
     * @throws SecurityException if log path is unsafe
     */
    public static void validateLogPath(String logPath) throws SecurityException {
        if (logPath == null || logPath.trim().isEmpty()) {
            return; // Optional parameter
        }
        
        validatePath(logPath);
        
        // Ensure log files are written to safe locations
        Path logFile = Paths.get(logPath).normalize().toAbsolutePath();
        String pathStr = logFile.toString();
        
        // Prevent writing to system locations
        String[] forbiddenLogPaths = {
            "/var/log/", "/etc/", "/bin/", "/sbin/",
            "C:\\Windows\\", "C:\\Program Files\\"
        };
        
        for (String forbidden : forbiddenLogPaths) {
            if (pathStr.startsWith(forbidden)) {
                throw new SecurityException("Log file cannot be written to system directory: " + logPath);
            }
        }
    }
    
    /**
     * Sanitizes strings for safe logging (removes potentially dangerous characters)
     * @param input The string to sanitize
     * @return Sanitized string safe for logging
     */
    public static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        
        // Remove or replace dangerous characters
        return input.replaceAll("[\r\n\t]", "_")           // Replace line breaks and tabs
                   .replaceAll("[\\x00-\\x1F\\x7F]", "")   // Remove control characters
                   .replaceAll("(?i)password=[^\\s;,]*", "password=****")    // Mask potential passwords
                   .replaceAll("(?i)secret=[^\\s;,]*", "secret=****")        // Mask potential secrets
                   .replaceAll("(?i)token=[^\\s;,]*", "token=****");         // Mask potential tokens
    }
    
    /**
     * Validates string input for general security (prevents injection attempts)
     * @param input The input string to validate
     * @param fieldName The name of the field being validated
     * @param maxLength Maximum allowed length
     * @throws SecurityException if input fails validation
     */
    public static void validateStringInput(String input, String fieldName, int maxLength) throws SecurityException {
        if (input == null) {
            throw new SecurityException(fieldName + " cannot be null");
        }
        
        if (input.length() > maxLength) {
            throw new SecurityException(fieldName + " exceeds maximum length: " + maxLength);
        }
        
        // Check for potentially dangerous characters
        if (input.contains("\0") || input.contains("\r") || input.contains("\n")) {
            throw new SecurityException(fieldName + " contains dangerous characters");
        }
        
        // Basic injection pattern detection
        String[] dangerousPatterns = {
            "<script", "javascript:", "data:", "vbscript:", "onload=", "onerror="
        };
        
        String lowerInput = input.toLowerCase();
        for (String pattern : dangerousPatterns) {
            if (lowerInput.contains(pattern)) {
                throw new SecurityException(fieldName + " contains potentially dangerous pattern: " + pattern);
            }
        }
    }
}