/*
 * AIAuditor.java
 * Author: Richard Hyunho Im (@richeeta), Route Zero Security
 * 
 * Core class for the AI Auditor Burp Suite extension. 
 * This class integrates with multiple Large Language Models (LLMs) to 
 * analyze HTTP requests and responses for security vulnerabilities. 
 * It manages API interactions, processes findings, and provides detailed
 * results for integration into Burp Suite's Scanner and other tools.
 * 
 * Version: 1.0
 * 
 * CHANGELOG: December 2, 2024
 * - FIXED: All models should correctly report issues in the Scanner now.
 * - FIXED: All API keys should now validate correctly.
 * - FIXED: Saved API keys should now persist on restart.
 */

package burp;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.*;
import java.util.List;
 
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import burp.api.montoya.core.Range;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
 
import javax.swing.*;
import java.awt.*;
 
public class AIAuditor implements BurpExtension, ContextMenuItemsProvider, ScanCheck {
    private static final String EXTENSION_NAME = "AI Auditor";
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 1000;
    private static final String PREF_PREFIX = "ai_auditor.";
     
     private MontoyaApi api;
     private PersistedObject persistedData;
     private ThreadPoolManager threadPoolManager;
     private volatile boolean isShuttingDown = false;
     
     // UI Components
    private JPanel mainPanel;
    private JPasswordField openaiKeyField;
    private JPasswordField geminiKeyField;
    private JPasswordField claudeKeyField;
    private JTextField localEndpointField;
    private JPasswordField localKeyField;
    private JComboBox<String> modelDropdown;
     private JTextArea promptTemplateArea;
     private JButton saveButton;
     private Registration menuRegistration;
     private Registration scanCheckRegistration;
 
     // Model Constants
     private static final Map<String, String> MODEL_MAPPING = new HashMap<String, String>() {{
        put("Default", "");
        put("gpt-4o", "openai");
        put("gpt-4o-mini", "openai");
        put("o1-preview", "openai");
        put("o1-mini", "openai");
        put("claude-3-opus-latest", "claude");
        put("claude-3-5-sonnet-latest", "claude");
        put("claude-3-5-haiku-latest", "claude");
        put("gemini-1.5-pro", "gemini");
        put("gemini-1.5-flash", "gemini");
        put("local-llm", "local");
    }};
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.threadPoolManager = new ThreadPoolManager(api);    
        api.logging().logToOutput("Extension initializing...");

        // Test preferences
        try {
            String testKey = "test_" + System.currentTimeMillis();
            api.persistence().preferences().setString(PREF_PREFIX + "test", testKey);
            String retrieved = api.persistence().preferences().getString(PREF_PREFIX + "test");
            api.logging().logToOutput("Preferences test: " + 
                (testKey.equals(retrieved) ? "PASSED" : "FAILED"));
        } catch (Exception e) {
            api.logging().logToError("Preferences test error: " + e.getMessage());
        }
        
        // Register extension capabilities
        api.extension().setName(EXTENSION_NAME);
        menuRegistration = api.userInterface().registerContextMenuItemsProvider(this);
        scanCheckRegistration = api.scanner().registerScanCheck(this);
        
        // Initialize UI and load settings
        SwingUtilities.invokeLater(() -> {
            api.logging().logToOutput("Creating main tab...");
            createMainTab();
            
            // Add a small delay before loading settings to ensure UI is ready
            javax.swing.Timer swingTimer = new javax.swing.Timer(500, e -> {
                api.logging().logToOutput("Loading saved settings...");
                loadSavedSettings();
                ((javax.swing.Timer)e.getSource()).stop();
            });
            swingTimer.setRepeats(false);
            swingTimer.start();
        });
        
        api.logging().logToOutput("Extension initialization complete");
    }
    private void cleanup() {
        isShuttingDown = true;
        if (threadPoolManager != null) {
            threadPoolManager.shutdown();
        }
        if (menuRegistration != null) {
            menuRegistration.deregister();
        }
        if (scanCheckRegistration != null) {
            scanCheckRegistration.deregister();
        }
    }

    private void createMainTab() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());

        // Create settings panel
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // API Keys and Local Endpoint
        int row = 0;
        addApiKeyField(settingsPanel, gbc, row++, "OpenAI API Key:", openaiKeyField = new JPasswordField(40), "openai");
        addApiKeyField(settingsPanel, gbc, row++, "Google API Key:", geminiKeyField = new JPasswordField(40), "gemini");
        addApiKeyField(settingsPanel, gbc, row++, "Anthropic API Key:", claudeKeyField = new JPasswordField(40), "claude");

        // Local model endpoint and key
        gbc.gridx = 0; gbc.gridy = row;
        settingsPanel.add(new JLabel("Local LLM Endpoint:"), gbc);
        localEndpointField = new JTextField(40);
        gbc.gridx = 1;
        settingsPanel.add(localEndpointField, gbc);
        row++;

        addApiKeyField(settingsPanel, gbc, row++, "Local LLM API Key:", localKeyField = new JPasswordField(40), "local");

        // Model Selection
        gbc.gridx = 0; gbc.gridy = row;
        settingsPanel.add(new JLabel("AI Model:"), gbc);
        modelDropdown = new JComboBox<>(new String[]{
            "Default",
            "claude-3-opus-latest",
            "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "local-llm",
            "gpt-4o-mini",
            "gpt-4o",
            "o1-preview",
            "o1-mini",
        });

        gbc.gridx = 1;
        settingsPanel.add(modelDropdown, gbc);

        // Custom Prompt Template
        gbc.gridx = 0; gbc.gridy = ++row;
        settingsPanel.add(new JLabel("Prompt Template:"), gbc);
        promptTemplateArea = new JTextArea(5, 40);
        promptTemplateArea.setLineWrap(true);
        promptTemplateArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(promptTemplateArea);
        gbc.gridx = 1;
        settingsPanel.add(scrollPane, gbc);

        // Save Button
        saveButton = new JButton("Save Settings");
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveSettings();
            }
        });
        gbc.gridx = 1; gbc.gridy = ++row;
        settingsPanel.add(saveButton, gbc);

        /* planned for future release
        JPanel statusPanel = new JPanel(new GridLayout(4, 1));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Status"));
        statusPanel.add(new JLabel("Active Tasks: 0"));
        statusPanel.add(new JLabel("Queued Tasks: 0"));
        statusPanel.add(new JLabel("Completed Tasks: 0"));
        statusPanel.add(new JLabel("Memory Usage: 0 MB")); */

        // Add panels to main panel
        mainPanel.add(settingsPanel, BorderLayout.CENTER);
        //mainPanel.add(statusPanel, BorderLayout.CENTER);

        // Register the tab
        api.userInterface().registerSuiteTab("AI Auditor", mainPanel);
    }

    private void addApiKeyField(JPanel panel, GridBagConstraints gbc, int row, String label, 
                              JPasswordField field, String provider) {
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        panel.add(field, gbc);
        JButton validateButton = new JButton("Validate");
        validateButton.addActionListener(e -> validateApiKey(provider));
        gbc.gridx = 2;
        panel.add(validateButton, gbc);
    }

    private void saveSettings() {
        api.logging().logToOutput("Starting saveSettings()...");
        
        try {
            // Get API keys from UI fields
            String openaiKey = new String(openaiKeyField.getPassword()).trim();
            String geminiKey = new String(geminiKeyField.getPassword()).trim();
            String claudeKey = new String(claudeKeyField.getPassword()).trim();
            String localKey = new String(localKeyField.getPassword()).trim();
            String localEndpoint = localEndpointField.getText().trim();
            
            // Check if at least one valid key is provided
            if (openaiKey.isEmpty() && geminiKey.isEmpty() && claudeKey.isEmpty() && localEndpoint.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel,
                        "Please provide at least one API key",
                        "Validation Error",
                        JOptionPane.WARNING_MESSAGE);
                });
                return;
            }
            
            // Save using Montoya preferences
            api.persistence().preferences().setString(PREF_PREFIX + "openai_key", openaiKey);
            api.persistence().preferences().setString(PREF_PREFIX + "gemini_key", geminiKey);
            api.persistence().preferences().setString(PREF_PREFIX + "claude_key", claudeKey);
            api.persistence().preferences().setString(PREF_PREFIX + "local_key", localKey);
            api.persistence().preferences().setString(PREF_PREFIX + "local_endpoint", localEndpoint);
            
            // Save selected model
            String selectedModel = (String) modelDropdown.getSelectedItem();
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model", selectedModel);
            
            // Save custom prompt if modified from default
            String currentPrompt = promptTemplateArea.getText();
            String defaultPrompt = getDefaultPromptTemplate();
            if (!currentPrompt.equals(defaultPrompt)) {
                api.persistence().preferences().setString(PREF_PREFIX + "custom_prompt", currentPrompt);
            }
            
            // Save timestamp
            api.persistence().preferences().setLong(PREF_PREFIX + "last_save", System.currentTimeMillis());
            
            // Verify saves were successful
            boolean allValid = verifySettings(openaiKey, geminiKey, claudeKey, localKey, localEndpoint);
            
            if (allValid) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel, 
                        "Settings saved successfully!", 
                        "Success", 
                        JOptionPane.INFORMATION_MESSAGE);
                });
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error saving settings: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "Error saving settings: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            });
        }
    }
    
    private boolean verifySettings(String openaiKey, String geminiKey, String claudeKey, String localKey, String localEndpoint) {
        boolean allValid = true;
        StringBuilder errors = new StringBuilder();
        
        // Verify each key was saved correctly
        String verifyOpenai = api.persistence().preferences().getString(PREF_PREFIX + "openai_key");
        if (!openaiKey.equals(verifyOpenai)) {
            allValid = false;
            errors.append("OpenAI key verification failed\n");
        }
        
        String verifyGemini = api.persistence().preferences().getString(PREF_PREFIX + "gemini_key"); 
        if (!geminiKey.equals(verifyGemini)) {
            allValid = false;
            errors.append("Gemini key verification failed\n");
        }
        
        String verifyClaude = api.persistence().preferences().getString(PREF_PREFIX + "claude_key");
        if (!claudeKey.equals(verifyClaude)) {
            allValid = false;
            errors.append("Claude key verification failed\n");
        }

        String verifyLocal = api.persistence().preferences().getString(PREF_PREFIX + "local_key");
        if (!localKey.equals(verifyLocal)) {
            allValid = false;
            errors.append("Local key verification failed\n");
        }

        String verifyEndpoint = api.persistence().preferences().getString(PREF_PREFIX + "local_endpoint");
        if (!localEndpoint.equals(verifyEndpoint)) {
            allValid = false;
            errors.append("Local endpoint verification failed\n");
        }
        
        if (!allValid) {
            api.logging().logToError("Settings verification failed:\n" + errors.toString());
        }
        
        return allValid;
    }
    
    private void loadSavedSettings() {
        api.logging().logToOutput("Starting loadSavedSettings()...");
        
        if (openaiKeyField == null || geminiKeyField == null || claudeKeyField == null || localEndpointField == null || localKeyField == null) {
            api.logging().logToError("Cannot load settings - UI components not initialized");
            return;
        }
        
        try {
            // Load API keys
            String openaiKey = api.persistence().preferences().getString(PREF_PREFIX + "openai_key");
            String geminiKey = api.persistence().preferences().getString(PREF_PREFIX + "gemini_key");
            String claudeKey = api.persistence().preferences().getString(PREF_PREFIX + "claude_key");
            String localKey = api.persistence().preferences().getString(PREF_PREFIX + "local_key");
            String localEndpoint = api.persistence().preferences().getString(PREF_PREFIX + "local_endpoint");
            
            // Load selected model
            String selectedModel = api.persistence().preferences().getString(PREF_PREFIX + "selected_model");
            
            // Load custom prompt if exists
            String customPrompt = api.persistence().preferences().getString(PREF_PREFIX + "custom_prompt");
            
            // Log retrieval status
            api.logging().logToOutput("Retrieved from preferences:");
            api.logging().logToOutput("- OpenAI key: " + (openaiKey != null ? "exists" : "null"));
            api.logging().logToOutput("- Gemini key: " + (geminiKey != null ? "exists" : "null"));
            api.logging().logToOutput("- Claude key: " + (claudeKey != null ? "exists" : "null"));
            api.logging().logToOutput("- Local endpoint: " + (localEndpoint != null ? localEndpoint : "null"));
            api.logging().logToOutput("- Selected model: " + selectedModel);
            
            // Update UI components
            SwingUtilities.invokeLater(() -> {
                // Set API keys
                openaiKeyField.setText(openaiKey != null ? openaiKey : "");
                geminiKeyField.setText(geminiKey != null ? geminiKey : "");
                claudeKeyField.setText(claudeKey != null ? claudeKey : "");
                localEndpointField.setText(localEndpoint != null ? localEndpoint : "");
                localKeyField.setText(localKey != null ? localKey : "");
                
                // Set selected model
                if (selectedModel != null && modelDropdown != null) {
                    modelDropdown.setSelectedItem(selectedModel);
                }
                
                // Set custom prompt if exists
                if (customPrompt != null && !customPrompt.isEmpty() && promptTemplateArea != null) {
                    promptTemplateArea.setText(customPrompt);
                }
                
                api.logging().logToOutput("UI fields updated with saved values");
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error loading settings: " + e.getMessage());
        }
    }
    
    private String getDefaultPromptTemplate() {
        return "You are an expert web application security researcher specializing in identifying high-impact vulnerabilities. " +
        "Analyze the provided HTTP request and response like a skilled bug bounty hunter, focusing on:\n\n" +
        "HIGH PRIORITY ISSUES:\n" +
        "1. Remote Code Execution (RCE) opportunities\n" +
        "2. SQL, NoSQL, command injection vectors\n" +
        "3. Authentication/Authorization bypasses\n" +
        "4. Insecure deserialization patterns\n" +
        "5. IDOR vulnerabilities (analyze ID patterns and access controls)\n" +
        "6. OAuth security issues (token exposure, implicit flow risks, state validation)\n" +
        "7. Sensitive information disclosure (tokens, credentials, internal paths)\n" +
        "8. XSS with demonstrable impact (focus on stored/reflected with actual risk)\n" +
        "9. CSRF in critical functions\n" +
        "10. Insecure cryptographic implementations\n" +
        "11. API endpoint security issues\n" +
        "12. Token entropy/predictability issues\n" +
        "+ Vulnerabilities that can directly be mapped to a CVE with public PoC and high-to-critical severity OWASP Top 10 vulnerabilities. \n\n" +
        "ANALYSIS GUIDELINES:\n" +
        "- Prioritize issues likely to be missed by Nessus, Nuclei, and Burp Scanner\n" +
        "- Focus on vulnerabilities requiring deep response analysis\n" +
        "- Report API endpoints found in JS files as INFORMATION level only\n" +
        "- Ignore low-impact findings like missing headers (CSP, cookie flags, absence of security headers)\n" +
        "- Skip theoretical issues without clear evidence\n" +
        "- Provide specific evidence, reproduction steps or specifically crafted proof of concept\n" +
        "- Include detailed technical context for each finding\n\n" +
               
        "SEVERITY CRITERIA:\n" +
        "HIGH: Immediate security impact (examples: RCE, auth bypass, MFA bypass, OAuth implicit flow, SSRF, critical data exposure, hardcoded secrets depending on context, command injection, insecure deserialization)\n" +
        "MEDIUM: Significant but not critical (examples: IDOR with limited scope, stored XSS, blind SSRF, blind injection, hardcoded secrets depending on context)\n" +
        "LOW: Valid security issue but limited impact (examples: Reflected XSS, HTML or CSS or DOM manipulation requiring user interaction)\n" +
        "INFORMATION: Useful security insights (API endpoints, potential attack surfaces)\n\n" +
          
        "CONFIDENCE CRITERIA:\n" +
        "CERTAIN: Over 95 percent confident with clear evidence and reproducible\n" +
        "FIRM: Over 60 percent confident with very strong indicators but needing additional validation\n" +
        "TENTATIVE: At least 50 percent confident with indicators warranting further investigation\n\n" +
             
        "Format findings as JSON with the following structure:\n" +
            "{\n" +
            "  \"findings\": [{\n" +
            "    \"vulnerability\": \"Clear, specific, concise title of issue\",\n" +
            "    \"location\": \"Exact location in request/response (parameter, header, or path)\",\n" +
            "    \"explanation\": \"Detailed technical explanation with evidence from the request/response\",\n" +
            "    \"exploitation\": \"Specific steps to reproduce/exploit\",\n" +
            "    \"validation_steps\": \"Steps to validate the finding\",\n" +
            "    \"severity\": \"HIGH|MEDIUM|LOW|INFORMATION\",\n" +
            "    \"confidence\": \"CERTAIN|FIRM|TENTATIVE\"\n" +
            "  }]\n" +
            "}\n\n" +
            
            "IMPORTANT:\n" +
            "- Only report findings with clear evidence in the request/response\n" +
            "- Issues below 50 percent confidence should not be reported unless severity is HIGH\n" +
            "- Include specific paths, parameters, or patterns that indicate the vulnerability\n" +
            "- For OAuth issues, carefully analyze token handling and flows (especially implicit flow)\n" +
            "- For IDOR, analyze ID patterns and access control mechanisms\n" +
            "- For injection points, provide exact payload locations\n" +
            "- Ignore hardcoded Google client ID, content security policy, strict transport security not enforced, cookie scoped to parent domain, cacheable HTTPS response, browser XSS filter disabled\n" +
            "- For sensitive info disclosure, specify exact data exposed\n" +
            "- Only return JSON with findings, no other content!";
    }
    
    private boolean validateApiKeyWithEndpoint(String apiKey, String endpoint, String jsonBody, String provider) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setRequestMethod(jsonBody.isEmpty() ? "GET" : "POST");
            conn.setRequestProperty("Content-Type", "application/json");
    
            // Add provider-specific headers
            if ("openai".equals(provider)) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            } else if ("claude".equals(provider)) {
                conn.setRequestProperty("x-api-key", apiKey);
                conn.setRequestProperty("anthropic-version", "2023-06-01");
            } else if ("local".equals(provider) && apiKey != null && !apiKey.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            }
    
            // Send request body if necessary
            if (!jsonBody.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }
    
            // Check response code
            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                return true;
            } else {
                // Log error response
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                    StringBuilder errorResponse = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        errorResponse.append(line);
                    }
                    api.logging().logToError("Validation failed: " + errorResponse);
                }
                return false;
            }
        } catch (Exception e) {
            api.logging().logToError("Error validating API key: " + e.getMessage());
            return false;
        }
    }
    
    
    private void validateApiKey(String provider) {
        String apiKey = "";
        String endpoint = "";
        String jsonBody = "";
        boolean isValid = false;
    
        try {
            switch (provider) {
                case "openai":
                    apiKey = openaiKeyField.getText();
                    endpoint = "https://api.openai.com/v1/models";
                    break;
    
                    case "gemini":
                    apiKey = geminiKeyField.getText();
                    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + apiKey;
                    jsonBody = "{"
                             + "  \"contents\": ["
                             + "    {\"parts\": [{\"text\": \"one plus one equals (respond with one integer only)\"}]}"
                             + "  ]"
                             + "}";
                    break;
                
    
                    case "claude":
                    apiKey = claudeKeyField.getText();
                    endpoint = "https://api.anthropic.com/v1/messages";
                    jsonBody = "{"
                             + "  \"model\": \"claude-3-5-sonnet-latest\","
                             + "  \"max_tokens\": 1024,"
                             + "  \"messages\": ["
                             + "    {\"role\": \"user\", \"content\": \"one plus one equals (respond with one integer only)\"}"
                             + "  ]"
                             + "}";
                    break;

                case "local":
                    apiKey = localKeyField.getText();
                    endpoint = localEndpointField.getText();
                    jsonBody = "{\"prompt\": \"ping\"}";
                    break;
                
    
                default:
                    JOptionPane.showMessageDialog(mainPanel, "Unknown provider: " + provider, "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
            }
    
            // Validate API key
            isValid = validateApiKeyWithEndpoint(apiKey, endpoint, jsonBody, provider);
    
            // Display result
            String message = isValid ? provider + " API key is valid" : provider + " API key validation failed";
            JOptionPane.showMessageDialog(mainPanel, message);
    
        } catch (Exception e) {
            api.logging().logToError("Error validating API key for " + provider + ": " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "Error validating API key: " + e.getMessage(), "Validation Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    
    
private void showValidationError(String message) {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(mainPanel, message, "Validation Error", JOptionPane.ERROR_MESSAGE));
    }
    
    private boolean performValidationRequest(String testEndpoint, String jsonBody, Map<String, String> headers) throws Exception {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(testEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(jsonBody.isEmpty() ? "GET" : "POST");
    
            // Set headers
            for (Map.Entry<String, String> header : headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }
    
            // Send body if applicable
            if (!jsonBody.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }
    
            // Log response for debugging
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                String responseMessage = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))
                    .lines().reduce("", String::concat);
                throw new Exception("API error " + responseCode + ": " + responseMessage);
            }
    
            return true;
    
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
    List<Component> menuItems = new ArrayList<>();

    // Handle Message Editor selection
    event.messageEditorRequestResponse().ifPresent(editor -> {
        HttpRequestResponse reqRes = editor.requestResponse();
        if (reqRes == null || reqRes.request() == null) {
            return;
        }

        // Check for text selection using selectionOffsets
        Optional<Range> selectionRange = editor.selectionOffsets();
        if (selectionRange.isPresent()) {
            JMenuItem scanSelected = new JMenuItem("AI Auditor > Scan Selected Portion");
            scanSelected.addActionListener(e -> handleSelectedScan(editor));
            menuItems.add(scanSelected);
        }

        // Add full scan option
        JMenuItem scanFull = new JMenuItem("AI Auditor > Scan Full Request/Response");
        scanFull.addActionListener(e -> handleFullScan(reqRes));
        menuItems.add(scanFull);
    });

    // Handle Proxy History / Site Map selection
    List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
    if (!selectedItems.isEmpty()) {
        if (selectedItems.size() == 1) {
            JMenuItem scanItem = new JMenuItem("AI Auditor > Scan Request/Response");
            scanItem.addActionListener(e -> handleFullScan(selectedItems.get(0)));
            menuItems.add(scanItem);
        } else {
            JMenuItem scanMultiple = new JMenuItem(String.format("AI Auditor > Scan %d Requests", selectedItems.size()));
            scanMultiple.addActionListener(e -> handleMultipleScan(selectedItems));
            menuItems.add(scanMultiple);
        }
    }

    return menuItems;
}

    private void handleSelectedScan(MessageEditorHttpRequestResponse editor) {
    try {
        Optional<Range> selectionRange = editor.selectionOffsets();
        if (!selectionRange.isPresent()) {
            return;
        }

        int start = selectionRange.get().startIndexInclusive();
        int end = selectionRange.get().endIndexExclusive();

        // Use editor content instead of reqRes.request()
        String editorContent = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                ? editor.requestResponse().request().toString()
                : editor.requestResponse().response() != null ? editor.requestResponse().response().toString() : "";

        // Ensure range is within bounds
        if (start >= 0 && end <= editorContent.length()) {
            String selectedContent = editorContent.substring(start, end);
            processAuditRequest(editor.requestResponse(), selectedContent, true);
        } else {
            throw new IndexOutOfBoundsException("Range [" + start + ", " + end + "] out of bounds for length " + editorContent.length());
        }
    } catch (Exception e) {
        api.logging().logToError("Error processing selected content: " + e.getMessage());
        showError("Error processing selected content", e);
    }
}


    

    private void handleFullScan(HttpRequestResponse reqRes) {
        if (reqRes == null || reqRes.request() == null) {
            return;
        }
        processAuditRequest(reqRes, null, false);
    }

    private void handleMultipleScan(List<HttpRequestResponse> requests) {
        if (requests == null || requests.isEmpty()) {
            return;
        }

        int batchSize = 5; // Process 5 requests at a time
        for (int i = 0; i < requests.size(); i += batchSize) {
            int endIndex = Math.min(i + batchSize, requests.size());
            List<HttpRequestResponse> batch = requests.subList(i, endIndex);
            
            for (HttpRequestResponse reqRes : batch) {
                if (reqRes != null && reqRes.request() != null) {
                    processAuditRequest(reqRes, null, false);
                }
            }

            // Add small delay between batches to prevent overwhelming
            if (endIndex < requests.size()) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void processAuditRequest(HttpRequestResponse reqRes, String selectedContent, boolean isSelectedPortion) {
        String selectedModel = getSelectedModel();
        String provider = MODEL_MAPPING.get(selectedModel);
        String apiKey = getApiKeyForModel(selectedModel);

        if ("local".equals(provider)) {
            if (localEndpointField.getText().trim().isEmpty()) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(mainPanel, "Local endpoint not configured"));
                return;
            }
        } else if (apiKey == null || apiKey.isEmpty()) {
            SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(mainPanel, "API key not configured for " + selectedModel));
            return;
        }
    
        CompletableFuture.runAsync(() -> {
            try {
                List<String> chunks;
                if (isSelectedPortion && selectedContent != null) {
                    chunks = RequestChunker.chunkContent(selectedContent);
                } else {
                    String request = reqRes.request().toString();
                    String response = reqRes.response() != null ? reqRes.response().toString() : "";
                    chunks = RequestChunker.chunkContent(request + "\n\n" + response);
                }
    
                // Create Set to track processed vulns
                Set<String> processedVulnerabilities = new HashSet<>();
    
                // Submit tasks to the thread pool for analysis
                List<CompletableFuture<JSONObject>> futures = new ArrayList<>();
                for (String chunk : chunks) {
                    futures.add(threadPoolManager.submitTask(provider,
                        () -> sendToAI(selectedModel, apiKey, chunk)));
                }
    
                // Process all chunkie cheeses and combine results
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .thenAccept(v -> {
                        try {
                            for (CompletableFuture<JSONObject> future : futures) {
                                JSONObject result = future.get();
                                processAIFindings(result, reqRes, processedVulnerabilities, selectedModel);
                            }
                        } catch (Exception e) {
                            api.logging().logToError("Error processing AI responses: " + e.getMessage());
                            showError("Error processing AI responses", e);
                        }
                    })
                    .exceptionally(e -> {
                        api.logging().logToError("Error in AI analysis: " + e.getMessage());
                        showError("Error in AI analysis", e);
                        return null;
                    });
    
            } catch (Exception e) {
                api.logging().logToError("Error in request processing: " + e.getMessage());
                showError("Error processing request", e);
            }
        }).exceptionally(e -> {
            api.logging().logToError("Critical error in request processing: " + e.getMessage());
            showError("Critical error", e);
            return null;
        });
    }
    

    private JSONObject sendToAI(String model, String apiKey, String content) throws Exception {
        String provider = MODEL_MAPPING.get(model);
        if (provider == null) {
            throw new IllegalArgumentException("Unsupported model: " + model);
        }
    
        URL url;
        JSONObject jsonBody = new JSONObject();
        String prompt = promptTemplateArea.getText();
    
        if (prompt == null || prompt.isEmpty()) {
            prompt = getDefaultPromptTemplate();
        }
    
        // Configure endpoint and payload
        switch (provider) {
            case "openai":
                url = new URL("https://api.openai.com/v1/chat/completions");
                jsonBody.put("model", model)
                        .put("messages", new JSONArray()
                            .put(new JSONObject()
                                .put("role", "user")
                                .put("content", prompt + "\n\nContent to analyze:\n" + content)));
                break;
    
            case "gemini":
                url = new URL("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey);
                jsonBody.put("contents", new JSONArray()
                        .put(new JSONObject()
                            .put("parts", new JSONArray()
                                .put(new JSONObject()
                                    .put("text", prompt + "\n\nContent to analyze:\n" + content)))));
                break;
    
            case "claude":
                url = new URL("https://api.anthropic.com/v1/messages");
                jsonBody.put("model", model)
                        .put("max_tokens", 1024)
                        .put("messages", new JSONArray()
                            .put(new JSONObject()
                                .put("role", "user")
                                .put("content", prompt + "\n\nContent to analyze:\n" + content)));
                break;

            case "local":
                url = new URL(localEndpointField.getText());
                jsonBody.put("prompt", prompt + "\n\nContent to analyze:\n" + content);
                break;

            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    
        // Retry logic
        Exception lastException = null;
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                return sendRequest(url, jsonBody, apiKey, model);
            } catch (Exception e) {
                lastException = e;
                api.logging().logToError("Attempt " + (attempt + 1) + " failed: " + e.getMessage());
                Thread.sleep(RETRY_DELAY_MS * (attempt + 1));
            }
        }
        throw new Exception("Failed after " + MAX_RETRIES + " attempts", lastException);
    }
    
    
    

    private JSONObject sendRequest(URL url, JSONObject jsonBody, String apiKey, String model) throws Exception {
    HttpURLConnection conn = null;
    BufferedReader reader = null;
    try {
        conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        String provider = MODEL_MAPPING.get(model);
        switch (provider) {
            case "claude":
                conn.setRequestProperty("x-api-key", apiKey);
                conn.setRequestProperty("anthropic-version", "2023-06-01");
                break;
            case "openai":
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                break;
            case "gemini":
                // Google API key is included in the URL bc ofc Google
                break;
            case "local":
                if (apiKey != null && !apiKey.isEmpty()) {
                    conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                }
                break;
        }

        // Send the request body
        if (jsonBody != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
        }

        // Read the response
        int responseCode = conn.getResponseCode();
        InputStream inputStream = (responseCode == 200) ? conn.getInputStream() : conn.getErrorStream();
        reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        StringBuilder responseBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            responseBuilder.append(line);
        }

        String responseContent = responseBuilder.toString();

        // Log the response for debugging
        api.logging().logToOutput("API Response: " + responseContent);

        if (responseCode == 200) {
            return new JSONObject(responseContent);
        } else {
            throw new Exception("API error " + responseCode + ": " + responseContent);
        }

    } finally {
        SafeUtils.closeQuietly(reader);
        SafeUtils.disconnectQuietly(conn);
    }
}

private void processAIFindings(JSONObject aiResponse, HttpRequestResponse requestResponse, Set<String> processedVulnerabilities, String model) {
    try {
        api.logging().logToOutput("AI Response: " + aiResponse.toString(2));

        // Extract content based on the provider
        String content = extractContentFromResponse(aiResponse, model);
        if (content == null || content.isEmpty()) {
            throw new JSONException("No valid content found in AI response.");
        }

        // Log raw content
        api.logging().logToOutput("Raw content: " + content);

        // Unwrap ```json ... ```
        if (content.startsWith("```json")) {
            content = content.substring(content.indexOf("{"), content.lastIndexOf("}") + 1);
        }

        api.logging().logToOutput("Extracted JSON: " + content);

        // Parse findings JSON
        JSONObject findingsJson = new JSONObject(content);

        // Ensure findings key exists
        if (!findingsJson.has("findings")) {
            throw new JSONException("Key 'findings' not found in extracted JSON.");
        }

        // Parse findings array
        JSONArray findings = findingsJson.getJSONArray("findings");

        for (int i = 0; i < findings.length(); i++) {
            JSONObject finding = findings.getJSONObject(i);

            // Skip duplicate vulns
            String hash = generateVulnerabilityHash(finding, requestResponse);
            if (processedVulnerabilities.contains(hash)) {
                continue;
            }
            processedVulnerabilities.add(hash);

            // Parse severity and confidence
            AuditIssueSeverity severity = parseSeverity(finding.getString("severity"));
            AuditIssueConfidence confidence = parseConfidence(finding.getString("confidence"));

            // Build issue details
            StringBuilder issueDetail = new StringBuilder();
            issueDetail.append("Issue identified by AI Auditor\n\n");
            issueDetail.append("Location: ").append(finding.optString("location", "Unknown")).append("\n\n");
            issueDetail.append("Detailed Explanation:\n").append(finding.optString("explanation", "No explanation provided")).append("\n\n");
            issueDetail.append("Confidence Level: ").append(confidence.name()).append("\n");
            issueDetail.append("Severity Level: ").append(severity.name());

            // Build AIAuditIssue
            AIAuditIssue issue = new AIAuditIssue.Builder()
                    .name("AI Audit: " + finding.optString("vulnerability", "Unknown Vulnerability"))
                    .detail(issueDetail.toString())
                    .endpoint(requestResponse.request().url())
                    .severity(severity)
                    .confidence(confidence)
                    .requestResponses(Collections.singletonList(requestResponse))
                    .modelUsed(model)
                    .build();

            // Add issue to sitemap
            api.siteMap().add(issue);
        }
    } catch (Exception e) {
        api.logging().logToError("Error processing AI findings: " + e.getMessage());
    }
}



private String extractContentFromResponse(JSONObject response, String model) {
    try {
        String provider = MODEL_MAPPING.get(model);
        if (provider == null) {
            throw new IllegalArgumentException("Unknown model: " + model);
        }

        // Log raw response for debugging
        api.logging().logToOutput("Raw response: " + response.toString());

        switch (provider) {
            case "claude":
                // Extract "text" for Claude
                if (response.has("content")) {
                    JSONArray contentArray = response.getJSONArray("content");
                    if (contentArray.length() > 0) {
                        return contentArray.getJSONObject(0).getString("text");
                    }
                }
                break;

            case "gemini":
                // Extract "text" under "candidates" > "content" > "parts" for Gemini
                JSONArray candidates = response.optJSONArray("candidates");
                if (candidates != null && candidates.length() > 0) {
                    JSONObject candidate = candidates.getJSONObject(0);
                    JSONObject content = candidate.optJSONObject("content");
                    if (content != null) {
                        JSONArray parts = content.optJSONArray("parts");
                        if (parts != null && parts.length() > 0) {
                            return parts.getJSONObject(0).getString("text");
                        }
                    }
                }
                break;

            case "openai":
                return response
                        .getJSONArray("choices")
                        .getJSONObject(0)
                        .getJSONObject("message")
                        .getString("content");

            case "local":
                return response.optString("content");

            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    } catch (Exception e) {
        api.logging().logToError("Error extracting content from response: " + e.getMessage());
    }
    return "";
}

private String formatFindingDetails(JSONObject finding) {
    if (finding == null) return "";

    StringBuilder details = new StringBuilder();
    details.append("<div style='font-family: Arial, sans-serif;'>");
    
    String location = SafeUtils.safeGetString(finding, "location");
    if (!location.isEmpty()) {
        details.append("<b>Location:</b><br/>")
               .append(escapeHtml(location))
               .append("<br/><br/>");
    }
    
    String explanation = SafeUtils.safeGetString(finding, "explanation");
    if (!explanation.isEmpty()) {
        details.append("<b>Technical Details:</b><br/>")
               .append(escapeHtml(explanation))
               .append("<br/><br/>");
    }

    String exploitation = SafeUtils.safeGetString(finding, "exploitation");
    if (!exploitation.isEmpty()) {
        details.append("<b>Exploitation Method:</b><br/>")
               .append(escapeHtml(exploitation))
               .append("<br/><br/>");
    }

    String validation = SafeUtils.safeGetString(finding, "validation_steps");
    if (!validation.isEmpty()) {
        details.append("<b>Validation Steps:</b><br/>")
               .append(escapeHtml(validation))
               .append("<br/><br/>");
    }

    details.append("<b>Confidence Level:</b> ")
           .append(SafeUtils.safeGetString(finding, "confidence"))
           .append("<br/>")
           .append("<b>Severity Level:</b> ")
           .append(SafeUtils.safeGetString(finding, "severity"));

    details.append("</div>");
    return details.toString();
}

private String escapeHtml(String text) {
    if (text == null) return "";
    return text.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace("\"", "&quot;")
              .replace("'", "&#39;")
              .replace("\n", "<br/>");
}

private String generateVulnerabilityHash(JSONObject finding, HttpRequestResponse reqRes) {
    String vulnerability = SafeUtils.safeGetString(finding, "vulnerability");
    String location = SafeUtils.safeGetString(finding, "location");
    String url = reqRes.request().url();

    return String.format("%s:%s:%s",
        vulnerability.isEmpty() ? "unknown" : vulnerability,
        location.isEmpty() ? "unknown" : location,
        url == null ? "unknown" : url
    ).hashCode() + "";
}

private AuditIssueSeverity parseSeverity(String severity) {
    switch (severity.toUpperCase()) {
        case "HIGH": return AuditIssueSeverity.HIGH;
        case "MEDIUM": return AuditIssueSeverity.MEDIUM;
        case "LOW": return AuditIssueSeverity.LOW;
        default: return AuditIssueSeverity.INFORMATION;
    }
}

private AuditIssueConfidence parseConfidence(String confidence) {
    switch (confidence.toUpperCase()) {
        case "CERTAIN": return AuditIssueConfidence.CERTAIN;
        case "FIRM": return AuditIssueConfidence.FIRM;
        default: return AuditIssueConfidence.TENTATIVE;
    }
}

private String getSelectedModel() {
    String model = (String) modelDropdown.getSelectedItem();
    if ("Default".equals(model)) {
        if (!new String(claudeKeyField.getPassword()).isEmpty()) return "claude-3-5-haiku-latest";
        if (!new String(openaiKeyField.getPassword()).isEmpty()) return "gpt-4o-mini"; // Set gpt-4o-mini as the default OpenAI model
        if (!new String(geminiKeyField.getPassword()).isEmpty()) return "gemini-1.5-flash";
    }
    return model;
}


private String getApiKeyForModel(String model) {
    String provider = MODEL_MAPPING.get(model);
    if (provider == null) {
        return null;
    }
    switch (provider) {
        case "openai": return new String(openaiKeyField.getPassword());
        case "gemini": return new String(geminiKeyField.getPassword());
        case "claude": return new String(claudeKeyField.getPassword());
        case "local": return new String(localKeyField.getPassword());
        default: return null;
    }
}



private void showError(String message, Throwable error) {
    api.logging().logToError(message + ": " + error.getMessage());
    SwingUtilities.invokeLater(() -> 
        JOptionPane.showMessageDialog(mainPanel,
            message + "\n" + error.getMessage(),
            "Error",
            JOptionPane.ERROR_MESSAGE));
}

@Override
public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
    // this extension doesn't implement active scanning (thank god)
    return AuditResult.auditResult(Collections.emptyList());
}

@Override
public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
    // this extension doesn't implement passive scanning (yet)
    return AuditResult.auditResult(Collections.emptyList());
}

@Override
public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
    if (newIssue.name().equals(existingIssue.name()) &&
        newIssue.detail().equals(existingIssue.detail()) &&
        newIssue.severity().equals(existingIssue.severity())) {
        return ConsolidationAction.KEEP_EXISTING;
    }
    return ConsolidationAction.KEEP_BOTH;
}
}
