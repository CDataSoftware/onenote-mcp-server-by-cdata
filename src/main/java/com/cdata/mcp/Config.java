package com.cdata.mcp;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import com.cdata.mcp.config.EnvironmentConfigurationProvider;
import com.cdata.mcp.config.SecretManager;
import com.cdata.mcp.config.ConfigurationSecurityReport;

import static com.cdata.mcp.StringUtil.isNullOrEmpty;

public class Config {
  private static final String PREFIX = "Prefix";
  private static final String DRIVER = "DriverClass";
  private static final String DRIVER_JAR = "DriverPath";
  private static final String JDBC_URL = "JdbcUrl";
  private static final String TABLES = "Tables";
  private static final String LOG_FILE = "LogFile";
  
  // Authentication configuration
  private static final String AUTH_REQUIRED = "AuthRequired";
  private static final String SESSION_TIMEOUT_MINUTES = "SessionTimeoutMinutes";
  
  // TLS configuration
  private static final String TLS_ENABLED = "TlsEnabled";
  private static final String HTTPS_PORT = "HttpsPort";
  private static final String KEYSTORE_PATH = "KeystorePath";
  private static final String KEYSTORE_PASSWORD = "KeystorePassword";
  private static final String KEYSTORE_TYPE = "KeystoreType";
  private static final String TRUSTSTORE_PATH = "TruststorePath";
  private static final String TRUSTSTORE_PASSWORD = "TruststorePassword";
  private static final String TRUSTSTORE_TYPE = "TruststoreType";
  private static final String CLIENT_AUTH_REQUIRED = "ClientAuthRequired";
  private static final String CLIENT_AUTH_WANTED = "ClientAuthWanted";

  // following properties will be discovered dynamically from driver
  private static final String ID_QUOTE_OPEN_CHAR = "IDENTIFIER_QUOTE_OPEN_CHAR";
  private static final String ID_QUOTE_CLOSE_CHAR = "IDENTIFIER_QUOTE_CLOSE_CHAR";
  private static final String SUPPORTS_MULTIPLE_CATALOGS = "SUPPORTS_MULTIPLE_CATALOGS";
  private static final String SUPPORTS_MULTIPLE_SCHEMAS = "SUPPORTS_MULTIPLE_SCHEMAS";
  private Properties props = new Properties();
  private Properties sqlInfo = new Properties();
  private Driver driver;
  private String defCatalog;
  private String defSchema;
  private ConnectionManager connectionManager;
  private com.cdata.mcp.auth.AuthenticationManager authenticationManager;
  private com.cdata.mcp.transport.TlsConfiguration tlsConfiguration;
  
  // Enhanced configuration management
  private EnvironmentConfigurationProvider envConfigProvider;
  private SecretManager secretManager;

  /**
   * Loads configuration with environment variable and secrets support
   * @param filepath Path to configuration file
   * @throws IOException if configuration cannot be loaded
   */
  public void load(String filepath) throws IOException {
    // Initialize enhanced configuration providers
    envConfigProvider = new EnvironmentConfigurationProvider();
    secretManager = new SecretManager(envConfigProvider);
    
    // Load configuration with security validation
    try {
      envConfigProvider.loadConfiguration(filepath);
      
      // Migrate properties to enhanced provider (backward compatibility)
      migrateToEnhancedConfiguration();
      
    } catch (SecurityException e) {
      throw new IOException("Security validation failed: " + e.getMessage(), e);
    }
  }
  
  /**
   * Migrates existing properties to enhanced configuration for backward compatibility
   */
  private void migrateToEnhancedConfiguration() {
    // Load legacy properties if they exist
    try (FileInputStream fis = new FileInputStream(getConfigFilePath())) {
      Properties legacyProps = new Properties();
      legacyProps.load(fis);
      
      // Copy to internal properties for legacy access
      for (String key : legacyProps.stringPropertyNames()) {
        props.setProperty(key, legacyProps.getProperty(key));
      }
    } catch (Exception e) {
      // Legacy file might not exist, continue with environment configuration
    }
  }
  
  /**
   * Gets the configuration file path from environment or default
   */
  private String getConfigFilePath() {
    return System.getenv("MCP_CONFIG_FILE") != null ? 
           System.getenv("MCP_CONFIG_FILE") : "config.properties";
  }

  public boolean validate(PrintStream errors) {
    boolean result = true;
    if (isNullOrEmpty(getPrefix())) {
      errors.println("The '" + PREFIX + "' option is missing");
      result = false;
    } else {
      // Validate prefix for security
      try {
        SecurityValidator.validateStringInput(getPrefix(), PREFIX, 50);
      } catch (SecurityException ex) {
        errors.println("Security validation failed for " + PREFIX + ": " + ex.getMessage());
        result = false;
      }
    }

    if (isNullOrEmpty(getDriver())) {
      errors.println("The '" + DRIVER + "' option is missing");
      result = false;
    } else {
      // Validate driver class is allowlisted
      try {
        SecurityValidator.validateDriverClass(getDriver());
      } catch (SecurityException ex) {
        errors.println("Security validation failed for " + DRIVER + ": " + ex.getMessage());
        result = false;
      }
    }

    if (isNullOrEmpty(getDriverJar())) {
      errors.println("The '" + DRIVER_JAR + "' option is missing");
      result = false;
    } else {
      // Validate JAR file security
      try {
        SecurityValidator.validateJarFile(getDriverJar());
      } catch (SecurityException ex) {
        errors.println("Security validation failed for " + DRIVER_JAR + ": " + ex.getMessage());
        result = false;
      }
      if (result && !verifyDriverLoad(errors)) {
        result = false;
      }
    }

    if (isNullOrEmpty(getJdbcUrl())) {
      errors.println("The '" + JDBC_URL + "' option is missing");
      result = false;
    } else {
      // Validate JDBC URL for security
      try {
        SecurityValidator.validateStringInput(getJdbcUrl(), JDBC_URL, 1000);
      } catch (SecurityException ex) {
        errors.println("Security validation failed for " + JDBC_URL + ": " + ex.getMessage());
        result = false;
      }
      if (result && !verifyJdbcUrl(errors)) {
        result = false;
      }
    }
    
    // Validate log file path if specified
    if (!isNullOrEmpty(getLogFile())) {
      try {
        SecurityValidator.validateLogPath(getLogFile());
      } catch (SecurityException ex) {
        errors.println("Security validation failed for " + LOG_FILE + ": " + ex.getMessage());
        result = false;
      }
    }
    
    return result;
  }

  public String getServerName() {
    return this.getPrefix();
  }
  public String getServerVersion() {
    return "1.0";
  }
  public String getPrefix() {
    if (envConfigProvider != null) {
      return envConfigProvider.getProperty(PREFIX, null);
    }
    return this.props.getProperty(PREFIX);
  }
  public String getMcpScheme() {
    return getPrefix() + "://";
  }
  public String getDriver() {
    if (envConfigProvider != null) {
      return envConfigProvider.getProperty(DRIVER, null);
    }
    return this.props.getProperty(DRIVER);
  }
  public String getDriverJar() {
    if (envConfigProvider != null) {
      return envConfigProvider.getProperty(DRIVER_JAR, null);
    }
    return this.props.getProperty(DRIVER_JAR);
  }
  public String getJdbcUrl() {
    if (envConfigProvider != null) {
      return envConfigProvider.getProperty(JDBC_URL, null);
    }
    return this.props.getProperty(JDBC_URL);
  }
  public List<Table> getTables() throws SQLException {
    String tables = this.props.getProperty(TABLES);
    if (isNullOrEmpty(tables)) {
      return new ArrayList<>();
    }
    List<Table> entries = Table.parseList(tables);
    return completeTableList(entries);
  }
  public String getIdentifierQuotes() {
    return this.sqlInfo.getProperty(ID_QUOTE_OPEN_CHAR)
        + this.sqlInfo.getProperty(ID_QUOTE_CLOSE_CHAR);
  }
  public boolean supportsMultipleCatalogs() {
    String val = this.sqlInfo.getProperty(SUPPORTS_MULTIPLE_CATALOGS);
    return val.equalsIgnoreCase("YES");
  }
  public boolean supportsMultipleSchemas() {
    String val = this.sqlInfo.getProperty(SUPPORTS_MULTIPLE_SCHEMAS);
    return val.equalsIgnoreCase("YES");
  }
  public String defaultCatalog() {
    return this.defCatalog;
  }
  public String defaultSchema() {
    return this.defSchema;
  }

  public String getLogFile() {
    if (envConfigProvider != null) {
      return envConfigProvider.getProperty(LOG_FILE, null);
    }
    return this.props.getProperty(LOG_FILE);
  }
  
  /**
   * Gets whether authentication is required
   * @return true if authentication is required (default: false)
   */
  public boolean isAuthRequired() {
    if (envConfigProvider != null) {
      return envConfigProvider.getBooleanProperty(AUTH_REQUIRED, false);
    }
    String value = this.props.getProperty(AUTH_REQUIRED, "false");
    return Boolean.parseBoolean(value);
  }
  
  /**
   * Gets the session timeout in minutes
   * @return session timeout in minutes (default: 60)
   */
  public long getSessionTimeoutMinutes() {
    if (envConfigProvider != null) {
      return envConfigProvider.getLongProperty(SESSION_TIMEOUT_MINUTES, 60L);
    }
    String value = this.props.getProperty(SESSION_TIMEOUT_MINUTES, "60");
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      return 60; // Default fallback
    }
  }
  
  /**
   * Gets the TLS configuration
   * @return TLS configuration
   */
  public com.cdata.mcp.transport.TlsConfiguration getTlsConfiguration() {
    if (tlsConfiguration == null) {
      tlsConfiguration = createTlsConfiguration();
    }
    return tlsConfiguration;
  }
  
  /**
   * Creates TLS configuration from properties with enhanced security support
   * @return TLS configuration
   */
  private com.cdata.mcp.transport.TlsConfiguration createTlsConfiguration() {
    com.cdata.mcp.transport.TlsConfiguration config = new com.cdata.mcp.transport.TlsConfiguration();
    
    // Basic TLS settings using enhanced configuration
    if (envConfigProvider != null) {
      config.setTlsEnabled(envConfigProvider.getBooleanProperty(TLS_ENABLED, false));
      
      if (config.isTlsEnabled()) {
        // HTTPS port
        config.setHttpsPort(envConfigProvider.getIntProperty(HTTPS_PORT, 8443));
        
        // Keystore settings with potential secret management
        config.setKeystorePath(getSecureProperty(KEYSTORE_PATH));
        config.setKeystorePassword(getSecureProperty(KEYSTORE_PASSWORD));
        config.setKeystoreType(envConfigProvider.getProperty(KEYSTORE_TYPE, "PKCS12"));
        
        // Truststore settings (optional)
        config.setTruststorePath(getSecureProperty(TRUSTSTORE_PATH));
        config.setTruststorePassword(getSecureProperty(TRUSTSTORE_PASSWORD));
        config.setTruststoreType(envConfigProvider.getProperty(TRUSTSTORE_TYPE, "PKCS12"));
        
        // Client authentication
        config.setClientAuthRequired(envConfigProvider.getBooleanProperty(CLIENT_AUTH_REQUIRED, false));
        config.setClientAuthWanted(envConfigProvider.getBooleanProperty(CLIENT_AUTH_WANTED, false));
      }
    } else {
      // Fallback to legacy properties
      config.setTlsEnabled(Boolean.parseBoolean(this.props.getProperty(TLS_ENABLED, "false")));
      
      if (config.isTlsEnabled()) {
        // HTTPS port
        String portStr = this.props.getProperty(HTTPS_PORT, "8443");
        try {
          config.setHttpsPort(Integer.parseInt(portStr));
        } catch (NumberFormatException e) {
          config.setHttpsPort(8443);
        }
        
        // Keystore settings
        config.setKeystorePath(this.props.getProperty(KEYSTORE_PATH));
        config.setKeystorePassword(this.props.getProperty(KEYSTORE_PASSWORD));
        config.setKeystoreType(this.props.getProperty(KEYSTORE_TYPE, "PKCS12"));
        
        // Truststore settings (optional)
        config.setTruststorePath(this.props.getProperty(TRUSTSTORE_PATH));
        config.setTruststorePassword(this.props.getProperty(TRUSTSTORE_PASSWORD));
        config.setTruststoreType(this.props.getProperty(TRUSTSTORE_TYPE, "PKCS12"));
        
        // Client authentication
        config.setClientAuthRequired(Boolean.parseBoolean(this.props.getProperty(CLIENT_AUTH_REQUIRED, "false")));
        config.setClientAuthWanted(Boolean.parseBoolean(this.props.getProperty(CLIENT_AUTH_WANTED, "false")));
      }
    }
    
    return config;
  }
  
  /**
   * Gets a secure property value, checking secrets management first
   * @param key The property key
   * @return The property value (from secrets or configuration)
   */
  private String getSecureProperty(String key) {
    // Try to get from secret manager first
    if (secretManager != null) {
      try {
        return secretManager.getSecret(key);
      } catch (SecretManager.SecretNotFoundException e) {
        // Fall back to configuration provider
      }
    }
    
    // Get from configuration provider
    return envConfigProvider != null ? 
           envConfigProvider.getProperty(key, null) : 
           this.props.getProperty(key);
  }

  public String quoteIdentifier(String id) {
    String open = this.sqlInfo.getProperty(ID_QUOTE_OPEN_CHAR);
    String close = this.sqlInfo.getProperty(ID_QUOTE_CLOSE_CHAR);
    
    // Properly escape identifier by doubling the close quote character
    String escapedId = id.replace(close, close + close);
    return open + escapedId + close;
  }

  public Connection newConnection() throws SQLException {
    return this.driver.connect(this.getJdbcUrl(), new Properties());
  }
  
  /**
   * Gets a managed connection with security controls and resource limits
   * @param clientId Identifier for the requesting client
   * @return A managed database connection
   * @throws SQLException if connection fails or limits are exceeded
   */
  public ManagedConnection getManagedConnection(String clientId) throws SQLException {
    if (connectionManager == null) {
      connectionManager = new ConnectionManager(this);
    }
    return connectionManager.getConnection(clientId);
  }
  
  /**
   * Gets the connection manager instance
   * @return The connection manager
   */
  public ConnectionManager getConnectionManager() {
    if (connectionManager == null) {
      connectionManager = new ConnectionManager(this);
    }
    return connectionManager;
  }
  
  /**
   * Gets the authentication manager instance
   * @return The authentication manager
   */
  public com.cdata.mcp.auth.AuthenticationManager getAuthenticationManager() {
    if (authenticationManager == null) {
      authenticationManager = new com.cdata.mcp.auth.AuthenticationManager(
          isAuthRequired(), 
          getSessionTimeoutMinutes()
      );
    }
    return authenticationManager;
  }
  
  /**
   * Gets the environment configuration provider
   * @return The environment configuration provider
   */
  public EnvironmentConfigurationProvider getEnvironmentConfigProvider() {
    return envConfigProvider;
  }
  
  /**
   * Gets the secret manager
   * @return The secret manager
   */
  public SecretManager getSecretManager() {
    return secretManager;
  }
  
  /**
   * Encrypts a configuration value for secure storage
   * @param plainText The plain text value to encrypt
   * @return Encrypted value suitable for configuration files
   */
  public String encryptConfigurationValue(String plainText) {
    if (envConfigProvider == null) {
      throw new IllegalStateException("Environment configuration provider not initialized");
    }
    return envConfigProvider.encryptValue(plainText);
  }
  
  /**
   * Validates the current configuration security
   * @return Configuration security report
   */
  public ConfigurationSecurityReport validateConfigurationSecurity() {
    ConfigurationSecurityReport report = new ConfigurationSecurityReport();
    
    // Check if sensitive values are encrypted
    if (envConfigProvider != null) {
      checkSensitiveProperty(KEYSTORE_PASSWORD, report);
      checkSensitiveProperty(TRUSTSTORE_PASSWORD, report);
      checkSensitiveProperty(JDBC_URL, report);
    }
    
    // Check secret manager availability
    if (secretManager != null) {
      report.setSecretManagerAvailable(secretManager.isConfigured());
      report.setAvailableProviders(secretManager.getAvailableProviders());
    }
    
    return report;
  }
  
  /**
   * Checks if a sensitive property is properly secured
   */
  private void checkSensitiveProperty(String propertyName, ConfigurationSecurityReport report) {
    String value = envConfigProvider.getProperty(propertyName, null);
    if (value != null && !envConfigProvider.isEncrypted(value)) {
      report.addUnsecuredProperty(propertyName);
    }
  }
  
  /**
   * Shuts down the connection manager and authentication manager
   */
  public void shutdown() {
    if (connectionManager != null) {
      connectionManager.shutdown();
    }
    if (authenticationManager != null) {
      authenticationManager.cleanupExpiredSessions();
    }
    if (secretManager != null) {
      secretManager.clearCache();
    }
  }

  private boolean verifyDriverLoad(PrintStream errors) {
    if (!new File(getDriverJar()).exists()) {
      errors.println("The '" + DRIVER_JAR + "' option is not a valid JAR file");
      return false;
    }
    try {
      loadDriver();
      return true;
    } catch (Throwable t) {
      String msg = t.getClass().getName() + ": " + t.getMessage();
      errors.println("Attempting to load the JDBC driver failed: " + msg);
    }
    return false;
  }

  private boolean verifyJdbcUrl(PrintStream errors) {
    try {
      try (Connection cn = newConnection()) {
      }
      return true;
    } catch ( SQLException ex ) {
      errors.println("Failed to open JDBC connection: " + ex.getMessage());
    }
    return false;
  }

  private void loadDriver() throws Exception {
    URLClassLoader ucl = new URLClassLoader(
        new URL[] {
            new File(this.getDriverJar()).toURI().toURL(),
        },
        this.getClass().getClassLoader()
    );
    Class dc = ucl.loadClass(this.getDriver());
    this.driver = (Driver)dc.getDeclaredConstructor().newInstance();

    loadSqlInfo();
  }

  private void loadSqlInfo() throws SQLException {
    try (Connection cn = newConnection()) {
      retrieveSqlInfo(cn);
      if (!this.supportsMultipleCatalogs()) {
        if (!this.supportsMultipleSchemas()) {
          retrieveDefaultCatalogAndSchema(cn);
        } else {
          retrieveDefaultCatalog(cn);
        }
      }
    }
  }

  private void retrieveDefaultCatalogAndSchema(Connection cn) throws SQLException {
    DatabaseMetaData meta = cn.getMetaData();
    try (ResultSet rs = meta.getSchemas()) {
      rs.next();
      this.defCatalog = rs.getString("TABLE_CATALOG");
      this.defSchema = rs.getString("TABLE_SCHEM");
    }
  }

  private void retrieveDefaultCatalog(Connection cn) throws SQLException {
    DatabaseMetaData meta = cn.getMetaData();
    try (ResultSet rs = meta.getCatalogs()) {
      rs.next();
      this.defCatalog = rs.getString(1);
    }
  }

  private void retrieveSqlInfo(Connection cn) throws SQLException {
    // Use PreparedStatement for better security practices, even though query is static
    String query = "SELECT NAME, VALUE FROM sys_sqlinfo";
    try (PreparedStatement ps = cn.prepareStatement(query)) {
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String key = rs.getString(1);
          String value = rs.getString(2);
          if (value == null) {
            value = "";
          }
          this.sqlInfo.put(key, value);
        }
      }
    }
  }

  private List<Table> completeTableList(List<Table> list) throws SQLException {
    List<Table> result = new ArrayList<>();
    try (Connection cn = newConnection()) {
      DatabaseMetaData meta = cn.getMetaData();
      // Not the most efficient, but oh well
      for (Table t : list) {
        addMatchingTables(t, meta, result);
      }
    }
    return result;
  }

  private void addMatchingTables(Table t, DatabaseMetaData meta, List<Table> result) throws SQLException {
    String catalog = t.hasCatalog() ? t.catalog() : null;
    String schema = t.hasSchema() ? t.schema() : null;
    String name = t.name();
    try (ResultSet rs = meta.getTables(catalog, schema, name, null)) {
      while (rs.next()) {
        catalog = rs.getString("TABLE_CAT");
        schema = rs.getString("TABLE_SCHEM");
        name = rs.getString("TABLE_NAME");
        result.add(new Table(catalog, schema, name));
      }
    }
  }
}
