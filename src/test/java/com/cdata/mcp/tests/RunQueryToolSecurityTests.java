package com.cdata.mcp.tests;

import com.cdata.mcp.Config;
import com.cdata.mcp.tools.RunQueryTool;
import org.junit.Test;
import org.junit.Before;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class RunQueryToolSecurityTests {
    
    private RunQueryTool tool;
    private Method validateSqlMethod;
    
    @Before
    public void setUp() throws Exception {
        Config mockConfig = new Config();
        tool = new RunQueryTool(mockConfig);
        
        // Use reflection to access private validateSql method for testing
        validateSqlMethod = RunQueryTool.class.getDeclaredMethod("validateSql", String.class);
        validateSqlMethod.setAccessible(true);
    }
    
    @Test
    public void testValidSelectQuery() throws Exception {
        String validQuery = "SELECT * FROM users WHERE age > 18";
        validateSqlMethod.invoke(tool, validQuery);
        // Should not throw exception
    }
    
    @Test
    public void testSelectWithJoin() throws Exception {
        String validQuery = "SELECT u.name, p.title FROM users u INNER JOIN posts p ON u.id = p.user_id";
        validateSqlMethod.invoke(tool, validQuery);
        // Should not throw exception
    }
    
    @Test(expected = SecurityException.class)
    public void testInsertQuery() throws Exception {
        String maliciousQuery = "INSERT INTO users (name) VALUES ('hacker')";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testUpdateQuery() throws Exception {
        String maliciousQuery = "UPDATE users SET password = 'hacked'";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testDeleteQuery() throws Exception {
        String maliciousQuery = "DELETE FROM users";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testDropTable() throws Exception {
        String maliciousQuery = "DROP TABLE users";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testSqlInjectionWithSemicolon() throws Exception {
        String maliciousQuery = "SELECT * FROM users; DROP TABLE users;";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testSqlComments() throws Exception {
        String maliciousQuery = "SELECT * FROM users /* comment */ WHERE 1=1";
        try {
            validateSqlMethod.invoke(tool, maliciousQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testEmptyQuery() throws Exception {
        String emptyQuery = "";
        try {
            validateSqlMethod.invoke(tool, emptyQuery);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testNullQuery() throws Exception {
        try {
            validateSqlMethod.invoke(tool, (String) null);
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
    
    @Test(expected = SecurityException.class)
    public void testExcessivelyLongQuery() throws Exception {
        StringBuilder longQuery = new StringBuilder("SELECT * FROM users WHERE ");
        for (int i = 0; i < 10000; i++) {
            longQuery.append("name = 'user").append(i).append("' OR ");
        }
        longQuery.append("1=1");
        
        try {
            validateSqlMethod.invoke(tool, longQuery.toString());
        } catch (Exception e) {
            throw (SecurityException) e.getCause();
        }
    }
}