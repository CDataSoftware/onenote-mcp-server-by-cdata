package com.cdata.mcp.tests;

import com.cdata.mcp.SecurityValidator;
import org.junit.Test;

import static org.junit.Assert.*;

public class SecurityValidatorTests {
    
    @Test
    public void testValidDriverClass() {
        // Should not throw exception for allowed driver
        SecurityValidator.validateDriverClass("cdata.jdbc.onenote.OneNoteDriver");
    }
    
    @Test(expected = SecurityException.class)
    public void testInvalidDriverClass() {
        SecurityValidator.validateDriverClass("malicious.driver.EvilDriver");
    }
    
    @Test(expected = SecurityException.class)
    public void testNullDriverClass() {
        SecurityValidator.validateDriverClass(null);
    }
    
    @Test(expected = SecurityException.class)
    public void testEmptyDriverClass() {
        SecurityValidator.validateDriverClass("");
    }
    
    @Test
    public void testValidStringInput() {
        SecurityValidator.validateStringInput("validInput", "testField", 100);
    }
    
    @Test(expected = SecurityException.class)
    public void testStringInputTooLong() {
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            longString.append("a");
        }
        SecurityValidator.validateStringInput(longString.toString(), "testField", 100);
    }
    
    @Test(expected = SecurityException.class)
    public void testStringInputWithNullByte() {
        SecurityValidator.validateStringInput("input\0withNull", "testField", 100);
    }
    
    @Test(expected = SecurityException.class)
    public void testStringInputWithScriptTag() {
        SecurityValidator.validateStringInput("<script>alert('xss')</script>", "testField", 100);
    }
    
    @Test
    public void testValidPath() {
        SecurityValidator.validatePath("/valid/path/to/file.jar");
    }
    
    @Test(expected = SecurityException.class)
    public void testPathTraversal() {
        SecurityValidator.validatePath("../../../etc/passwd");
    }
    
    @Test(expected = SecurityException.class)
    public void testSystemDirectoryAccess() {
        SecurityValidator.validatePath("/etc/shadow");
    }
    
    @Test
    public void testValidLogPath() {
        SecurityValidator.validateLogPath("/home/user/logs/app.log");
    }
    
    @Test(expected = SecurityException.class)
    public void testInvalidLogPath() {
        SecurityValidator.validateLogPath("/var/log/system.log");
    }
    
    @Test
    public void testSanitizeForLogging() {
        String input = "password=secret123 and token=abc123\nwith\nnewlines";
        String sanitized = SecurityValidator.sanitizeForLogging(input);
        
        assertFalse("Password should be masked", sanitized.contains("secret123"));
        assertFalse("Token should be masked", sanitized.contains("abc123"));
        assertFalse("Should not contain newlines", sanitized.contains("\n"));
        assertTrue("Should contain masked password", sanitized.contains("password=****"));
        assertTrue("Should contain masked token", sanitized.contains("token=****"));
    }
    
    @Test
    public void testSanitizeNullInput() {
        String result = SecurityValidator.sanitizeForLogging(null);
        assertEquals("null", result);
    }
}