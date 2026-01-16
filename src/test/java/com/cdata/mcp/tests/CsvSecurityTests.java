package com.cdata.mcp.tests;

import com.cdata.mcp.CsvWriter;
import org.junit.Test;

import static org.junit.Assert.*;

public class CsvSecurityTests {
    
    @Test
    public void testNormalCsvOutput() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("normal").column("data").end();
        
        String result = writer.end();
        assertTrue("Should contain normal data", result.contains("\"normal\",\"data\""));
    }
    
    @Test
    public void testFormulaInjectionPrevention() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("=SUM(A1:A10)").end();
        
        String result = writer.end();
        assertTrue("Formula should be neutralized", result.contains("'=SUM(A1:A10)"));
    }
    
    @Test
    public void testPlusInjectionPrevention() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("+cmd|'/c calc'!A0").end();
        
        String result = writer.end();
        assertTrue("Plus injection should be neutralized", result.contains("'+cmd"));
    }
    
    @Test
    public void testMinusInjectionPrevention() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("-2+3+cmd|'/c calc'!A0").end();
        
        String result = writer.end();
        assertTrue("Minus injection should be neutralized", result.contains("'-2+3"));
    }
    
    @Test
    public void testAtInjectionPrevention() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("@SUM(1+1)*cmd|'/c calc'!A0").end();
        
        String result = writer.end();
        assertTrue("At injection should be neutralized", result.contains("'@SUM"));
    }
    
    @Test
    public void testControlCharacterRemoval() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("data\rwith\ncontrol\0chars").end();
        
        String result = writer.end();
        // The CSV writer adds a newline at the end of rows, so we check the content
        String[] lines = result.split("\n");
        String csvLine = lines[0];
        assertFalse("Should not contain carriage return in data", csvLine.contains("\r"));
        assertFalse("Should not contain null byte", csvLine.contains("\0"));
        assertTrue("Should contain spaces instead", csvLine.contains("data with control"));
    }
    
    @Test
    public void testLongFieldTruncation() {
        StringBuilder longField = new StringBuilder();
        for (int i = 0; i < 40000; i++) {
            longField.append("A");
        }
        
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column(longField.toString()).end();
        
        String result = writer.end();
        assertTrue("Long field should be truncated", result.contains("(truncated)"));
    }
    
    @Test
    public void testCommandInjectionDetection() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("=cmd|'/c calc'").end();
        
        String result = writer.end();
        assertTrue("Command injection should be neutralized", result.contains("'=cmd"));
    }
    
    @Test
    public void testPowershellInjectionDetection() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("data=powershell.exe").end();
        
        String result = writer.end();
        assertTrue("PowerShell injection should be neutralized", result.contains("'data=powershell"));
    }
    
    @Test
    public void testScriptInjectionDetection() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("value=script:alert('xss')").end();
        
        String result = writer.end();
        assertTrue("Script injection should be neutralized", result.contains("'value=script"));
    }
    
    @Test
    public void testNullValueHandling() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column(null).column("test").end();
        
        String result = writer.end();
        assertTrue("Should handle null values with empty field", result.contains("\"test\""));
    }
    
    @Test
    public void testEmptyValueHandling() {
        CsvWriter writer = new CsvWriter();
        CsvWriter.Row row = writer.row();
        row.column("").column("test").end();
        
        String result = writer.end();
        assertTrue("Should handle empty values", result.contains("\"test\""));
    }
}