package com.cdata.mcp.tools;

import com.cdata.mcp.*;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class RunQueryTool implements ITool {
  private Config config;
  private Logger logger = LoggerFactory.getLogger(RunQueryTool.class);
  
  // SQL security validation patterns and allowlists
  private static final Set<String> ALLOWED_KEYWORDS = new HashSet<>(Arrays.asList(
      "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "LIKE", "IS", "NULL",
      "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "TOP", "DISTINCT",
      "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "JOIN", "ON", "AS", "ASC", "DESC",
      "UNION", "ALL", "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "CONVERT",
      "COUNT", "SUM", "AVG", "MIN", "MAX", "UPPER", "LOWER", "TRIM", "SUBSTRING"
  ));
  
  private static final Set<String> FORBIDDEN_KEYWORDS = new HashSet<>(Arrays.asList(
      "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE",
      "EXEC", "EXECUTE", "CALL", "PROCEDURE", "FUNCTION", "DECLARE", "SET",
      "GRANT", "REVOKE", "COMMIT", "ROLLBACK", "TRANSACTION", "MERGE", "UPSERT"
  ));
  
  // Pattern to detect potentially dangerous SQL constructs
  private static final Pattern DANGEROUS_PATTERNS = Pattern.compile(
      "(?i)(;|--|/\\*|\\*/|xp_|sp_cmdshell|@@|char\\(|nchar\\(|ascii\\(|waitfor\\s+delay)",
      Pattern.CASE_INSENSITIVE
  );

  public RunQueryTool(Config config) {
    this.config = config;
  }

  @Override
  public void register(McpServer.SyncSpec mcp) throws Exception {
    String quotes = this.config.getIdentifierQuotes();
    String prefix = this.config.getPrefix();
    String description = "The SELECT statement to execute. "
        + "Use the `" + prefix + "_get_tables` tool to get a list of available tables, "
        + "and the `" + prefix + "_get_columns` tool to list table columns. "
        + "The SQL dialect is mostly based around SQL-92. "
        + "Identifiers should be quoted using `" + quotes + "` characters. "
        + "Valid clauses: FROM, INNER JOIN, LEFT JOIN, GROUP BY, ORDER BY, LIMIT/OFFSET. "
        + Constants.FORMAT_DESC;

    String schema = new JsonSchemaBuilder()
        .addString("sql", description)
        .build();
    mcp.tool(
        new Tool(
            prefix + "_run_query",
            "Execute a SQL SELECT statement.",
            schema
        ),
        this::run
    );
  }

  @Override
  public McpSchema.CallToolResult run(Map<String, Object> args) {
    String sql = (String)args.get("sql");
    
    // Validate SQL before logging to prevent log injection
    try {
      validateSql(sql);
    } catch (SecurityException ex) {
      throw new RuntimeException("SECURITY_ERROR: " + ex.getMessage());
    }
    
    this.logger.info("RunQueryTool - executing validated SELECT query");
    try {
      try (ManagedConnection cn = config.getManagedConnection("RunQueryTool")) {
        List<McpSchema.Content> content = new ArrayList<>();
        String csv = queryToCsv(cn, sql);

        List<McpSchema.Role> roles = new ArrayList<>();
        roles.add(McpSchema.Role.USER);
        content.add(
            new McpSchema.TextContent(roles, 1.0, csv)
        );
        return new McpSchema.CallToolResult(content, false);
      }
    } catch ( Exception ex ) {
      throw new RuntimeException("Database operation failed: " + sanitizeErrorMessage(ex.getMessage()));
    }
  }

  private String queryToCsv(Connection cn, String sql) throws SQLException {
    try (Statement st = cn.createStatement()) {
      return CsvUtils.resultSetToCsv(st.executeQuery(sql));
    }
  }

  /**
   * Validates SQL query to prevent injection attacks and ensure only SELECT operations
   * @param sql The SQL query to validate
   * @throws SecurityException if the SQL is deemed unsafe
   */
  private void validateSql(String sql) throws SecurityException {
    if (sql == null || sql.trim().isEmpty()) {
      throw new SecurityException("SQL query cannot be null or empty");
    }

    String normalizedSql = sql.trim().toUpperCase();
    
    // Must start with SELECT
    if (!normalizedSql.startsWith("SELECT")) {
      throw new SecurityException("Only SELECT statements are allowed");
    }

    // Check for dangerous patterns
    if (DANGEROUS_PATTERNS.matcher(sql).find()) {
      throw new SecurityException("SQL contains potentially dangerous constructs");
    }

    // Check for forbidden keywords
    String[] tokens = normalizedSql.split("\\s+");
    for (String token : tokens) {
      String cleanToken = token.replaceAll("[^A-Z0-9_]", "");
      if (FORBIDDEN_KEYWORDS.contains(cleanToken)) {
        throw new SecurityException("Forbidden SQL keyword detected: " + cleanToken);
      }
    }

    // Additional length check to prevent extremely long queries
    if (sql.length() > 10000) {
      throw new SecurityException("SQL query exceeds maximum allowed length");
    }

    // Check for multiple statements (basic check)
    String withoutStrings = removeStringLiterals(sql);
    if (withoutStrings.contains(";")) {
      throw new SecurityException("Multiple SQL statements are not allowed");
    }
  }

  /**
   * Remove string literals from SQL to check for semicolons outside of strings
   * @param sql The SQL query
   * @return SQL with string literals removed
   */
  private String removeStringLiterals(String sql) {
    StringBuilder result = new StringBuilder();
    boolean inSingleQuote = false;
    boolean inDoubleQuote = false;
    
    for (int i = 0; i < sql.length(); i++) {
      char c = sql.charAt(i);
      
      if (c == '\'' && !inDoubleQuote) {
        inSingleQuote = !inSingleQuote;
      } else if (c == '"' && !inSingleQuote) {
        inDoubleQuote = !inDoubleQuote;
      } else if (!inSingleQuote && !inDoubleQuote) {
        result.append(c);
      }
    }
    
    return result.toString();
  }

  /**
   * Sanitizes error messages to prevent information disclosure
   * @param errorMessage The original error message
   * @return Sanitized error message
   */
  private String sanitizeErrorMessage(String errorMessage) {
    if (errorMessage == null) {
      return "Unknown database error";
    }
    
    // Remove potentially sensitive information from error messages
    String sanitized = errorMessage
        .replaceAll("password=[^\\s;,]+", "password=****")
        .replaceAll("token=[^\\s;,]+", "token=****")
        .replaceAll("secret=[^\\s;,]+", "secret=****")
        .replaceAll("jdbc:[^\\s;,]+", "jdbc:****")
        .replaceAll("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", "***.***.***.**")  // IP addresses
        .replaceAll("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b", "****@****.***");  // Email addresses
    
    // Limit error message length
    if (sanitized.length() > 200) {
      sanitized = sanitized.substring(0, 200) + "... (truncated)";
    }
    
    return sanitized;
  }

}
