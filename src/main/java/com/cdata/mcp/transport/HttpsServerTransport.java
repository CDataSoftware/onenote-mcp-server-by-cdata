package com.cdata.mcp.transport;

import com.cdata.mcp.auth.AuthenticationManager;
import com.cdata.mcp.auth.ClientInfo;
import com.cdata.mcp.auth.Session;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.ServerMcpTransport;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * HTTPS server transport for MCP with TLS encryption and security headers
 * Supports HTTP/2, client authentication, and comprehensive security configuration
 */
public class HttpsServerTransport implements ServerMcpTransport {
    
    private static final Logger logger = LoggerFactory.getLogger(HttpsServerTransport.class);
    
    @Override
    public <T> T unmarshalFrom(Object data, com.fasterxml.jackson.core.type.TypeReference<T> typeRef) {
        try {
            return objectMapper.convertValue(data, typeRef);
        } catch (Exception e) {
            throw new RuntimeException("Failed to unmarshal data", e);
        }
    }
    
    @Override
    public reactor.core.publisher.Mono<Void> sendMessage(io.modelcontextprotocol.spec.McpSchema.JSONRPCMessage message) {
        // For HTTPS transport, messages are sent via HTTP response
        // This method is called by the MCP framework to send responses
        // In our implementation, responses are handled directly in servlet methods
        logger.debug("Message queued for HTTP response: {}", message);
        return reactor.core.publisher.Mono.empty();
    }
    
    @Override
    public reactor.core.publisher.Mono<Void> closeGracefully() {
        try {
            stop();
            return reactor.core.publisher.Mono.empty();
        } catch (Exception e) {
            return reactor.core.publisher.Mono.error(e);
        }
    }
    
    private final TlsConfiguration tlsConfig;
    private final AuthenticationManager authManager;
    private final ObjectMapper objectMapper;
    private Server server;
    
    public HttpsServerTransport(TlsConfiguration tlsConfig, AuthenticationManager authManager, ObjectMapper objectMapper) {
        this.tlsConfig = tlsConfig;
        this.authManager = authManager;
        this.objectMapper = objectMapper;
    }
    
    /**
     * Starts the HTTPS server
     * @throws Exception if server startup fails
     */
    public void start() throws Exception {
        tlsConfig.validate();
        
        server = new Server();
        
        // Create SSL context factory
        SslContextFactory.Server sslContextFactory = createSslContextFactory();
        
        // Create server connectors
        ServerConnector httpsConnector = createHttpsConnector(server, sslContextFactory);
        server.addConnector(httpsConnector);
        
        // Create servlet context
        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        
        // Add MCP servlet
        ServletHolder mcpServletHolder = new ServletHolder(new McpServlet());
        context.addServlet(mcpServletHolder, "/mcp/*");
        
        // Add health check servlet
        ServletHolder healthServletHolder = new ServletHolder(new HealthCheckServlet());
        context.addServlet(healthServletHolder, "/health");
        
        server.setHandler(context);
        
        // Start server
        server.start();
        
        logger.info("HTTPS MCP server started on port {} with TLS enabled", tlsConfig.getHttpsPort());
        
        // Log certificate information
        logCertificateInfo();
    }
    
    /**
     * Stops the HTTPS server
     * @throws Exception if server shutdown fails
     */
    public void stop() throws Exception {
        if (server != null && server.isRunning()) {
            server.stop();
            logger.info("HTTPS MCP server stopped");
        }
    }
    
    /**
     * Creates the SSL context factory with security configuration
     * @return Configured SSL context factory
     * @throws Exception if SSL configuration fails
     */
    private SslContextFactory.Server createSslContextFactory() throws Exception {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        
        // Load SSL context
        SSLContext sslContext = CertificateManager.createSSLContext(tlsConfig);
        sslContextFactory.setSslContext(sslContext);
        
        // Configure keystore
        sslContextFactory.setKeyStorePath(tlsConfig.getKeystorePath());
        sslContextFactory.setKeyStorePassword(tlsConfig.getKeystorePassword());
        sslContextFactory.setKeyStoreType(tlsConfig.getKeystoreType());
        
        // Configure truststore if specified
        if (tlsConfig.getTruststorePath() != null && !tlsConfig.getTruststorePath().trim().isEmpty()) {
            sslContextFactory.setTrustStorePath(tlsConfig.getTruststorePath());
            sslContextFactory.setTrustStorePassword(tlsConfig.getTruststorePassword());
            sslContextFactory.setTrustStoreType(tlsConfig.getTruststoreType());
        }
        
        // Configure client authentication
        if (tlsConfig.isClientAuthRequired()) {
            sslContextFactory.setNeedClientAuth(true);
        } else if (tlsConfig.isClientAuthWanted()) {
            sslContextFactory.setWantClientAuth(true);
        }
        
        // Configure protocols
        sslContextFactory.setIncludeProtocols(tlsConfig.getEnabledProtocols().toArray(new String[0]));
        
        // Configure cipher suites
        sslContextFactory.setIncludeCipherSuites(tlsConfig.getEnabledCipherSuites().toArray(new String[0]));
        
        // Security settings
        sslContextFactory.setRenegotiationAllowed(false);
        sslContextFactory.setSessionCachingEnabled(true);
        sslContextFactory.setSslSessionTimeout(300); // 5 minutes
        
        return sslContextFactory;
    }
    
    /**
     * Creates the HTTPS connector with HTTP/2 support
     * @param server The Jetty server
     * @param sslContextFactory The SSL context factory
     * @return Configured HTTPS connector
     */
    private ServerConnector createHttpsConnector(Server server, SslContextFactory.Server sslContextFactory) {
        // HTTP/2 support
        HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(new HttpConfiguration());
        
        // ALPN (Application-Layer Protocol Negotiation)
        ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
        alpn.setDefaultProtocol("h2");
        
        // HTTPS configuration
        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.setSecureScheme("https");
        httpsConfig.setSecurePort(tlsConfig.getHttpsPort());
        httpsConfig.addCustomizer(new SecureRequestCustomizer());
        
        // Add security headers customizer
        if (tlsConfig.isEnableSecurityHeaders()) {
            httpsConfig.addCustomizer(new SecurityHeadersCustomizer(tlsConfig));
        }
        
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpsConfig);
        SslConnectionFactory sslConnectionFactory = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());
        
        ServerConnector httpsConnector = new ServerConnector(server, sslConnectionFactory, alpn, h2, http11);
        httpsConnector.setPort(tlsConfig.getHttpsPort());
        
        return httpsConnector;
    }
    
    /**
     * Logs certificate information for monitoring
     */
    private void logCertificateInfo() {
        try {
            CertificateManager.CertificateValidationResult validation = 
                CertificateManager.validateCertificates(
                    tlsConfig.getKeystorePath(), 
                    tlsConfig.getKeystorePassword(), 
                    tlsConfig.getKeystoreType()
                );
            
            for (CertificateManager.CertificateInfo cert : validation.getCertificates()) {
                logger.info("Certificate loaded: {} (expires: {})", cert.getSubject(), cert.getNotAfter());
                
                if (cert.isExpiredSoon()) {
                    logger.warn("Certificate expires soon: {} (expires: {})", cert.getAlias(), cert.getNotAfter());
                }
            }
            
            for (String warning : validation.getWarnings()) {
                logger.warn("Certificate warning: {}", warning);
            }
            
            for (String error : validation.getErrors()) {
                logger.error("Certificate error: {}", error);
            }
            
        } catch (Exception e) {
            logger.warn("Failed to validate certificates: {}", e.getMessage());
        }
    }
    
    /**
     * Main MCP servlet that handles MCP protocol over HTTPS
     */
    private class McpServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            
            // Extract client information
            ClientInfo clientInfo = extractClientInfo(request);
            
            // Authenticate request
            Session session = authenticateRequest(request, clientInfo);
            if (session == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Authentication required\"}");
                return;
            }
            
            // Add security headers
            addSecurityHeaders(response);
            
            // Process MCP request (placeholder)
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("{\"result\":\"MCP request processed\"}");
            
            logger.debug("MCP request processed for user: {}", session.getUserName());
        }
        
        @Override
        protected void doOptions(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Handle CORS preflight
            addSecurityHeaders(response);
            response.setStatus(HttpServletResponse.SC_OK);
        }
    }
    
    /**
     * Health check servlet
     */
    private class HealthCheckServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            
            addSecurityHeaders(response);
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            
            PrintWriter writer = response.getWriter();
            writer.write("{\"status\":\"healthy\",\"transport\":\"https\",\"tls\":true}");
        }
    }
    
    /**
     * Extracts client information from the HTTP request
     * @param request The HTTP request
     * @return Client information
     */
    private ClientInfo extractClientInfo(HttpServletRequest request) {
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String hostname = request.getRemoteHost();
        
        return new ClientInfo(ipAddress, userAgent, hostname);
    }
    
    /**
     * Gets the real client IP address, considering proxies
     * @param request The HTTP request
     * @return Client IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        // Check for X-Forwarded-For header (load balancers/proxies)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Take the first IP in the chain
            return xForwardedFor.split(",")[0].trim();
        }
        
        // Check for X-Real-IP header (nginx)
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        // Fall back to remote address
        return request.getRemoteAddr();
    }
    
    /**
     * Authenticates the HTTP request
     * @param request The HTTP request
     * @param clientInfo Client information
     * @return Authenticated session, or null if authentication fails
     */
    private Session authenticateRequest(HttpServletRequest request, ClientInfo clientInfo) {
        if (authManager == null) {
            return null; // No authentication manager configured
        }
        
        // Check for session token in header
        String sessionToken = request.getHeader("X-Session-Token");
        if (sessionToken != null) {
            return authManager.validateSession(sessionToken);
        }
        
        // Check for API key in header
        String apiKey = request.getHeader("X-API-Key");
        if (apiKey != null) {
            try {
                var authResult = authManager.authenticate(apiKey, clientInfo);
                if (authResult.isSuccessful()) {
                    return authManager.validateSession(authResult.getSessionToken());
                }
            } catch (Exception e) {
                logger.warn("Authentication failed for client {}: {}", clientInfo.getIpAddress(), e.getMessage());
            }
        }
        
        return null;
    }
    
    /**
     * Adds security headers to the HTTP response
     * @param response The HTTP response
     */
    private void addSecurityHeaders(HttpServletResponse response) {
        if (!tlsConfig.isEnableSecurityHeaders()) {
            return;
        }
        
        // HSTS (HTTP Strict Transport Security)
        if (tlsConfig.isEnableHsts()) {
            response.setHeader("Strict-Transport-Security", 
                             String.format("max-age=%d; includeSubDomains", tlsConfig.getHstsMaxAge()));
        }
        
        // Content Security Policy
        response.setHeader("Content-Security-Policy", "default-src 'self'");
        
        // Prevent MIME type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        // XSS Protection
        response.setHeader("X-XSS-Protection", "1; mode=block");
        
        // Frame options
        response.setHeader("X-Frame-Options", "DENY");
        
        // Referrer policy
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Permissions policy
        response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    }
    
    @Override
    public void close() {
        try {
            stop();
        } catch (Exception e) {
            throw new RuntimeException("Failed to close HTTPS transport", e);
        }
    }
    
    /**
     * Custom security headers handler
     */
    private static class SecurityHeadersCustomizer implements HttpConfiguration.Customizer {
        private final TlsConfiguration tlsConfig;
        
        public SecurityHeadersCustomizer(TlsConfiguration tlsConfig) {
            this.tlsConfig = tlsConfig;
        }
        
        @Override
        public Request customize(Request request, HttpFields.Mutable responseFields) {
            // Additional request-level security customization can be added here
            return request;
        }
    }
}