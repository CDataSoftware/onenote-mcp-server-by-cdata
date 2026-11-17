package com.cdata.mcp;

import java.util.regex.Pattern;

/**
 * Secure CSV writer that prevents CSV injection attacks
 * Sanitizes potentially dangerous content and validates data
 */
public class CsvWriter {
  private StringBuilder buffer = new StringBuilder();
  
  // CSV injection patterns that could be dangerous
  private static final Pattern DANGEROUS_CSV_PATTERNS = Pattern.compile(
      "^[=+\\-@].*", Pattern.CASE_INSENSITIVE
  );
  
  // Maximum field length to prevent resource exhaustion
  private static final int MAX_FIELD_LENGTH = 32768; // 32KB per field

  public Row row() {
    return new Row();
  }

  public String end() {
    return this.buffer.toString();
  }

  public class Row {
    private StringBuilder row = new StringBuilder();

    public Row column(String value) {
      if (row.length() > 0) {
        row.append(',');
      }
      if (value != null && value.length() > 0) {
        String sanitizedValue = sanitizeValue(value);
        quote(sanitizedValue);
      }
      return this;
    }

    public void end() {
      buffer.append(this.row)
          .append("\n");
    }
    private void quote(String val) {
      row.append('"');
      for (int i=0; i < val.length(); i++) {
        char ch = val.charAt(i);
        if (ch == '"') {
          row.append(ch); // Double the quote for proper CSV escaping
        }
        row.append(ch);
      }
      row.append('"');
    }
    
    /**
     * Sanitizes CSV field values to prevent injection attacks
     * @param value The original field value
     * @return Sanitized field value safe for CSV output
     */
    private String sanitizeValue(String value) {
      if (value == null) {
        return "";
      }
      
      // Limit field length to prevent resource exhaustion
      if (value.length() > MAX_FIELD_LENGTH) {
        value = value.substring(0, MAX_FIELD_LENGTH) + "... (truncated)";
      }
      
      // Remove or neutralize potentially dangerous characters
      String sanitized = value
          .replace("\0", "")           // Remove null bytes
          .replace("\r", " ")          // Replace carriage returns with spaces
          .replace("\n", " ");         // Replace line feeds with spaces
      
      // Check for CSV injection patterns and neutralize them
      if (DANGEROUS_CSV_PATTERNS.matcher(sanitized).matches()) {
        // Prepend with single quote to neutralize formula injection
        sanitized = "'" + sanitized;
      }
      
      // Additional check for other potentially dangerous patterns
      if (sanitized.contains("=") && sanitized.length() > 1) {
        // If the field contains = and looks like a formula, neutralize it
        if (sanitized.startsWith("=") || 
            sanitized.contains("cmd") || 
            sanitized.contains("powershell") ||
            sanitized.contains("bash") ||
            sanitized.contains("sh ") ||
            sanitized.toLowerCase().contains("script")) {
          sanitized = "'" + sanitized; // Neutralize by prepending quote
        }
      }
      
      return sanitized;
    }
  }
}
