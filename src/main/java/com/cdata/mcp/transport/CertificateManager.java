package com.cdata.mcp.transport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Manages SSL/TLS certificates and keystore operations
 * Provides utilities for certificate validation, expiration checking, and SSL context creation
 */
public class CertificateManager {
    private static final Logger logger = LoggerFactory.getLogger(CertificateManager.class);
    
    /**
     * Creates an SSL context from the provided TLS configuration
     * @param tlsConfig The TLS configuration
     * @return Configured SSL context
     * @throws TlsConfigurationException if SSL context creation fails
     */
    public static SSLContext createSSLContext(TlsConfiguration tlsConfig) throws TlsConfigurationException {
        try {
            // Load keystore
            KeyManagerFactory keyManagerFactory = createKeyManagerFactory(tlsConfig);
            
            // Load truststore (optional)
            TrustManagerFactory trustManagerFactory = null;
            if (tlsConfig.getTruststorePath() != null && !tlsConfig.getTruststorePath().trim().isEmpty()) {
                trustManagerFactory = createTrustManagerFactory(tlsConfig);
            }
            
            // Create SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory != null ? trustManagerFactory.getTrustManagers() : null,
                new SecureRandom()
            );
            
            return sslContext;
            
        } catch (Exception e) {
            throw new TlsConfigurationException("Failed to create SSL context", e);
        }
    }
    
    /**
     * Creates a KeyManagerFactory from the keystore configuration
     * @param tlsConfig The TLS configuration
     * @return Configured KeyManagerFactory
     * @throws Exception if keystore loading fails
     */
    private static KeyManagerFactory createKeyManagerFactory(TlsConfiguration tlsConfig) throws Exception {
        KeyStore keystore = KeyStore.getInstance(tlsConfig.getKeystoreType());
        
        try (FileInputStream keystoreStream = new FileInputStream(tlsConfig.getKeystorePath())) {
            keystore.load(keystoreStream, tlsConfig.getKeystorePassword().toCharArray());
        }
        
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, tlsConfig.getKeystorePassword().toCharArray());
        
        logger.info("Loaded keystore: {} (type: {})", tlsConfig.getKeystorePath(), tlsConfig.getKeystoreType());
        
        return keyManagerFactory;
    }
    
    /**
     * Creates a TrustManagerFactory from the truststore configuration
     * @param tlsConfig The TLS configuration
     * @return Configured TrustManagerFactory
     * @throws Exception if truststore loading fails
     */
    private static TrustManagerFactory createTrustManagerFactory(TlsConfiguration tlsConfig) throws Exception {
        KeyStore truststore = KeyStore.getInstance(tlsConfig.getTruststoreType());
        
        try (FileInputStream truststoreStream = new FileInputStream(tlsConfig.getTruststorePath())) {
            truststore.load(truststoreStream, tlsConfig.getTruststorePassword().toCharArray());
        }
        
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(truststore);
        
        logger.info("Loaded truststore: {} (type: {})", tlsConfig.getTruststorePath(), tlsConfig.getTruststoreType());
        
        return trustManagerFactory;
    }
    
    /**
     * Validates certificates in a keystore for expiration and other issues
     * @param keystorePath Path to the keystore
     * @param keystorePassword Password for the keystore
     * @param keystoreType Type of keystore (e.g., PKCS12, JKS)
     * @return Certificate validation result
     */
    public static CertificateValidationResult validateCertificates(String keystorePath, String keystorePassword, String keystoreType) {
        List<String> warnings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        List<CertificateInfo> certificates = new ArrayList<>();
        
        try {
            KeyStore keystore = KeyStore.getInstance(keystoreType);
            
            try (FileInputStream keystoreStream = new FileInputStream(keystorePath)) {
                keystore.load(keystoreStream, keystorePassword.toCharArray());
            }
            
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                if (keystore.isCertificateEntry(alias) || keystore.isKeyEntry(alias)) {
                    Certificate cert = keystore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509Cert = (X509Certificate) cert;
                        CertificateInfo certInfo = analyzeCertificate(alias, x509Cert);
                        certificates.add(certInfo);
                        
                        // Check for expiration warnings
                        if (certInfo.isExpiredSoon()) {
                            warnings.add(String.format("Certificate '%s' expires soon: %s", alias, certInfo.getNotAfter()));
                        }
                        
                        if (certInfo.isExpired()) {
                            errors.add(String.format("Certificate '%s' has expired: %s", alias, certInfo.getNotAfter()));
                        }
                        
                        // Check for weak signature algorithms
                        if (isWeakSignatureAlgorithm(x509Cert.getSigAlgName())) {
                            warnings.add(String.format("Certificate '%s' uses weak signature algorithm: %s", alias, x509Cert.getSigAlgName()));
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            errors.add("Failed to validate certificates: " + e.getMessage());
        }
        
        return new CertificateValidationResult(certificates, warnings, errors);
    }
    
    /**
     * Analyzes a single X.509 certificate
     * @param alias The certificate alias
     * @param cert The X.509 certificate
     * @return Certificate information
     */
    private static CertificateInfo analyzeCertificate(String alias, X509Certificate cert) {
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();
        Instant now = Instant.now();
        
        boolean expired = now.isAfter(notAfter);
        boolean expiredSoon = !expired && now.isAfter(notAfter.minus(30, ChronoUnit.DAYS));
        
        return new CertificateInfo(
            alias,
            cert.getSubjectX500Principal().getName(),
            cert.getIssuerX500Principal().getName(),
            notBefore,
            notAfter,
            cert.getSigAlgName(),
            expired,
            expiredSoon
        );
    }
    
    /**
     * Checks if a signature algorithm is considered weak
     * @param algorithm The signature algorithm name
     * @return true if the algorithm is weak
     */
    private static boolean isWeakSignatureAlgorithm(String algorithm) {
        if (algorithm == null) {
            return true;
        }
        
        String alg = algorithm.toUpperCase();
        return alg.contains("MD5") || 
               alg.contains("SHA1") || 
               alg.contains("1024");
    }
    
    /**
     * Generates a self-signed certificate and saves it to a keystore
     * This is primarily for development and testing purposes
     * @param keystorePath Path where the keystore will be created
     * @param keystorePassword Password for the keystore
     * @param hostname Hostname for the certificate
     * @throws TlsConfigurationException if certificate generation fails
     */
    public static void generateSelfSignedCertificate(String keystorePath, String keystorePassword, String hostname) 
            throws TlsConfigurationException {
        try {
            // This is a placeholder - in a real implementation, you would use
            // libraries like Bouncy Castle to generate certificates
            logger.warn("Self-signed certificate generation not implemented in this example");
            logger.warn("Please use keytool or openssl to generate certificates:");
            logger.warn("keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -keystore {} -dname 'CN={}' -validity 365", 
                       keystorePath, hostname);
            
            throw new TlsConfigurationException("Self-signed certificate generation not implemented. Use keytool manually.");
            
        } catch (Exception e) {
            throw new TlsConfigurationException("Failed to generate self-signed certificate", e);
        }
    }
    
    /**
     * Information about a certificate
     */
    public static class CertificateInfo {
        private final String alias;
        private final String subject;
        private final String issuer;
        private final Instant notBefore;
        private final Instant notAfter;
        private final String signatureAlgorithm;
        private final boolean expired;
        private final boolean expiredSoon;
        
        public CertificateInfo(String alias, String subject, String issuer, Instant notBefore, 
                             Instant notAfter, String signatureAlgorithm, boolean expired, boolean expiredSoon) {
            this.alias = alias;
            this.subject = subject;
            this.issuer = issuer;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.signatureAlgorithm = signatureAlgorithm;
            this.expired = expired;
            this.expiredSoon = expiredSoon;
        }
        
        // Getters
        public String getAlias() { return alias; }
        public String getSubject() { return subject; }
        public String getIssuer() { return issuer; }
        public Instant getNotBefore() { return notBefore; }
        public Instant getNotAfter() { return notAfter; }
        public String getSignatureAlgorithm() { return signatureAlgorithm; }
        public boolean isExpired() { return expired; }
        public boolean isExpiredSoon() { return expiredSoon; }
        
        @Override
        public String toString() {
            return String.format("Certificate[alias=%s, subject=%s, expires=%s, expired=%s]",
                               alias, subject, notAfter, expired);
        }
    }
    
    /**
     * Result of certificate validation
     */
    public static class CertificateValidationResult {
        private final List<CertificateInfo> certificates;
        private final List<String> warnings;
        private final List<String> errors;
        
        public CertificateValidationResult(List<CertificateInfo> certificates, List<String> warnings, List<String> errors) {
            this.certificates = Collections.unmodifiableList(certificates);
            this.warnings = Collections.unmodifiableList(warnings);
            this.errors = Collections.unmodifiableList(errors);
        }
        
        public List<CertificateInfo> getCertificates() { return certificates; }
        public List<String> getWarnings() { return warnings; }
        public List<String> getErrors() { return errors; }
        
        public boolean hasErrors() { return !errors.isEmpty(); }
        public boolean hasWarnings() { return !warnings.isEmpty(); }
        
        @Override
        public String toString() {
            return String.format("CertificateValidation[certs=%d, warnings=%d, errors=%d]",
                               certificates.size(), warnings.size(), errors.size());
        }
    }
}