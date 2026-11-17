package com.cdata.mcp.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Report on the security status of configuration properties
 */
public class ConfigurationSecurityReport {
    private boolean secretManagerAvailable = false;
    private Map<String, Boolean> availableProviders;
    private final List<String> unsecuredProperties = new ArrayList<>();
    private final List<String> recommendations = new ArrayList<>();
    
    public ConfigurationSecurityReport() {
        // Default recommendations
        recommendations.add("Use environment variables for sensitive configuration");
        recommendations.add("Encrypt sensitive values in configuration files");
        recommendations.add("Set up external secret management (Vault, AWS Secrets Manager)");
        recommendations.add("Validate configuration file permissions (600 or 640)");
    }
    
    /**
     * Checks if the configuration is secure
     * @return true if configuration is considered secure
     */
    public boolean isSecure() {
        return unsecuredProperties.isEmpty() && (secretManagerAvailable || hasEncryptedValues());
    }
    
    /**
     * Gets the security score (0-100)
     * @return Security score
     */
    public int getSecurityScore() {
        int score = 100;
        
        // Deduct points for unsecured properties
        score -= unsecuredProperties.size() * 20;
        
        // Deduct points if no secret manager available
        if (!secretManagerAvailable) {
            score -= 20;
        }
        
        // Ensure score doesn't go below 0
        return Math.max(0, score);
    }
    
    /**
     * Gets the security level description
     * @return Security level string
     */
    public String getSecurityLevel() {
        int score = getSecurityScore();
        if (score >= 90) return "EXCELLENT";
        if (score >= 70) return "GOOD";
        if (score >= 50) return "FAIR";
        if (score >= 30) return "POOR";
        return "CRITICAL";
    }
    
    /**
     * Adds an unsecured property to the report
     * @param propertyName The property name
     */
    public void addUnsecuredProperty(String propertyName) {
        if (!unsecuredProperties.contains(propertyName)) {
            unsecuredProperties.add(propertyName);
        }
    }
    
    /**
     * Gets the list of unsecured properties
     * @return List of unsecured property names
     */
    public List<String> getUnsecuredProperties() {
        return new ArrayList<>(unsecuredProperties);
    }
    
    /**
     * Sets whether secret manager is available
     * @param available true if secret manager is configured
     */
    public void setSecretManagerAvailable(boolean available) {
        this.secretManagerAvailable = available;
    }
    
    /**
     * Checks if secret manager is available
     * @return true if secret manager is available
     */
    public boolean isSecretManagerAvailable() {
        return secretManagerAvailable;
    }
    
    /**
     * Sets the available secret providers
     * @param providers Map of provider names to availability
     */
    public void setAvailableProviders(Map<String, Boolean> providers) {
        this.availableProviders = providers;
    }
    
    /**
     * Gets the available secret providers
     * @return Map of provider names to availability
     */
    public Map<String, Boolean> getAvailableProviders() {
        return availableProviders;
    }
    
    /**
     * Gets security recommendations
     * @return List of recommendations
     */
    public List<String> getRecommendations() {
        List<String> allRecommendations = new ArrayList<>(recommendations);
        
        // Add specific recommendations based on findings
        if (!unsecuredProperties.isEmpty()) {
            allRecommendations.add("Encrypt the following properties: " + 
                                 String.join(", ", unsecuredProperties));
        }
        
        if (!secretManagerAvailable) {
            allRecommendations.add("Configure external secret management for enhanced security");
        }
        
        return allRecommendations;
    }
    
    /**
     * Adds a custom recommendation
     * @param recommendation The recommendation text
     */
    public void addRecommendation(String recommendation) {
        if (!recommendations.contains(recommendation)) {
            recommendations.add(recommendation);
        }
    }
    
    /**
     * Checks if configuration has encrypted values
     * @return true if at least some values are encrypted
     */
    private boolean hasEncryptedValues() {
        // This would need to be implemented based on actual configuration scanning
        // For now, assume false to encourage proper setup
        return false;
    }
    
    /**
     * Generates a summary report
     * @return Report summary string
     */
    public String generateSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Configuration Security Report\n");
        summary.append("============================\n");
        summary.append(String.format("Security Level: %s (%d/100)\n", getSecurityLevel(), getSecurityScore()));
        summary.append(String.format("Secret Manager: %s\n", secretManagerAvailable ? "Available" : "Not Configured"));
        
        if (availableProviders != null && !availableProviders.isEmpty()) {
            summary.append("Available Providers:\n");
            for (Map.Entry<String, Boolean> entry : availableProviders.entrySet()) {
                summary.append(String.format("  - %s: %s\n", 
                             entry.getKey(), 
                             entry.getValue() ? "Available" : "Not Configured"));
            }
        }
        
        if (!unsecuredProperties.isEmpty()) {
            summary.append("\nUnsecured Properties:\n");
            for (String prop : unsecuredProperties) {
                summary.append(String.format("  - %s\n", prop));
            }
        }
        
        summary.append("\nRecommendations:\n");
        for (String rec : getRecommendations()) {
            summary.append(String.format("  - %s\n", rec));
        }
        
        return summary.toString();
    }
    
    @Override
    public String toString() {
        return String.format("ConfigurationSecurityReport[secure=%s, score=%d, unsecured=%d, secretManager=%s]",
                           isSecure(), getSecurityScore(), unsecuredProperties.size(), secretManagerAvailable);
    }
}