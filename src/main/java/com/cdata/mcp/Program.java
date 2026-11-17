package com.cdata.mcp;

import java.sql.SQLException;
import java.util.List;

import com.cdata.mcp.resources.TableMetadataResource;
import com.cdata.mcp.tools.GetColumnsTool;
import com.cdata.mcp.tools.GetTablesTool;
import com.cdata.mcp.tools.RunQueryTool;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransport;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.ServerMcpTransport;

public class Program {
  
  private ServerMcpTransport transport;
  private Config config;
  private McpSyncServer mcpServer;
  private static final boolean STDIO = true;

  public void init(String configPath) throws Exception {
    this.config = new Config();
    this.config.load(configPath);
    
    // Configure secure logging
    configureSecureLogging();
    
    if (!this.config.validate(System.err)) {
      System.exit(-1);
    }

    this.transport = new StdioServerTransport(new ObjectMapper());
  }
  
  private void configureSecureLogging() {
    if (!StringUtil.isNullOrEmpty(this.config.getLogFile())) {
      try {
        // Validate log file path for security
        SecurityValidator.validateLogPath(this.config.getLogFile());
        
        // Set logging properties securely
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info"); // Changed from debug to info
        System.setProperty("org.slf4j.simpleLogger.logFile", this.config.getLogFile());
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd HH:mm:ss");
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.showLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        
      } catch (SecurityException ex) {
        System.err.println("Security validation failed for log file: " + ex.getMessage());
        System.err.println("Logging to console instead");
        // Fall back to console logging
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
      }
    } else {
      // Default to console logging with appropriate level
      System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
    }
  }

  public void configureMcp() throws Exception {
    McpServer.SyncSpec spec =
        McpServer.sync(this.transport)
            .serverInfo(this.config.getServerName(), this.config.getServerVersion())
            .capabilities(
                McpSchema.ServerCapabilities.builder()
                    .tools(true)
                    .resources(false, true)
                    //.logging()
                    .build()
            );

    registerResources(this.config, spec);
    registerTools(this.config, spec);

    this.mcpServer = spec.build();
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Usage: <properties-file-path>");
      System.exit(-1);
    }
    String path = args[0];

    final Program p = new Program();
    p.init(args[0]);
    p.configureMcp();
    if (!STDIO) {
      //p.runHttpServer();
    } else {
      Runtime.getRuntime().addShutdownHook(new Thread() {
        public void run() {
          System.err.println("Shutting down MCP server...");
          try {
            // Close the MCP server gracefully
            if (p.mcpServer != null) {
              p.mcpServer.closeGracefully();
            }
            
            // Shutdown connection manager
            if (p.config != null) {
              p.config.shutdown();
            }
            
            System.err.println("MCP server shutdown complete");
          } catch (Exception e) {
            System.err.println("Error during shutdown: " + e.getMessage());
          } finally {
            synchronized (p) {
              p.notify();
            }
          }
        }
      });
      
      try {
        synchronized (p) {
          p.wait();
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        System.err.println("Main thread interrupted");
      }
    }
  }

  private static void registerResources(Config config, McpServer.SyncSpec mcp) throws SQLException {
    List<Table> tables = config.getTables();
    TableMetadataResource resource = new TableMetadataResource(config);

    for (Table r : tables) {
      resource.register(mcp, r);
    }
  }
  private static void registerTools(Config config, McpServer.SyncSpec mcp) throws Exception {
    ITool[] tools = new ITool[] {
        new GetTablesTool(config),
        new GetColumnsTool(config),
        new RunQueryTool(config)
    };
    for (ITool tool : tools) {
      if (tool != null) {
        tool.register(mcp);
      }
    }
  }
}