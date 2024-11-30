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
 * Date: November 28, 2024
 */

 package burp;

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
     
     private MontoyaApi api;
     private PersistedObject persistedData;
     private ThreadPoolManager threadPoolManager;
     private volatile boolean isShuttingDown = false;
     
     // UI Components
     private JPanel mainPanel;
     private JPasswordField openaiKeyField;
     private JPasswordField geminiKeyField;
     private JPasswordField claudeKeyField;
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
        put("claude-3-sonnet-latest", "claude");
        put("claude-3-haiku-latest", "claude");
        put("claude-3-5-sonnet-latest", "claude");
        put("claude-3-5-haiku-latest", "claude");
        put("gemini-1.5-pro", "gemini");
        put("gemini-1.5-flash", "gemini");
    }};
    
    

     @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.persistedData = api.persistence().extensionData();
        this.threadPoolManager = new ThreadPoolManager(api);
        
        // Register extension capabilities
        api.extension().setName(EXTENSION_NAME);
        menuRegistration = api.userInterface().registerContextMenuItemsProvider(this);
        scanCheckRegistration = api.scanner().registerScanCheck(this);
        
        // Initialize UI
        SwingUtilities.invokeLater(this::createMainTab);
        loadSavedSettings();
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
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

        // API Keys
        addApiKeyField(settingsPanel, gbc, 0, "OpenAI API Key:", openaiKeyField = new JPasswordField(40), "openai");
        addApiKeyField(settingsPanel, gbc, 1, "Google API Key:", geminiKeyField = new JPasswordField(40), "gemini");
        addApiKeyField(settingsPanel, gbc, 2, "Anthropic API Key:", claudeKeyField = new JPasswordField(40), "claude");

        // Model Selection
        gbc.gridx = 0; gbc.gridy = 3;
        settingsPanel.add(new JLabel("AI Model:"), gbc);
        modelDropdown = new JComboBox<>(new String[]{
            "Default",
            "claude-3-opus-latest",
            "claude-3-sonnet-latest",
            "claude-3-haiku-latest",
            "claude-3-5-sonnet-latest", // New
            "claude-3-5-haiku-latest",  // New
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gpt-4o-mini",
            "gpt-4o",
            "o1-preview",
            "o1-mini",
        });
        
        gbc.gridx = 1;
        settingsPanel.add(modelDropdown, gbc);

        // Custom Prompt Template
        gbc.gridx = 0; gbc.gridy = 4;
        settingsPanel.add(new JLabel("Prompt Template:"), gbc);
        promptTemplateArea = new JTextArea(5, 40);
        promptTemplateArea.setLineWrap(true);
        promptTemplateArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(promptTemplateArea);
        gbc.gridx = 1;
        settingsPanel.add(scrollPane, gbc);

        // Save Button
        saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        gbc.gridx = 1; gbc.gridy = 5;
        settingsPanel.add(saveButton, gbc);

        // Status Panel
        JPanel statusPanel = new JPanel(new GridLayout(4, 1));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Status"));
        statusPanel.add(new JLabel("Active Tasks: 0"));
        statusPanel.add(new JLabel("Queued Tasks: 0"));
        statusPanel.add(new JLabel("Completed Tasks: 0"));
        statusPanel.add(new JLabel("Memory Usage: 0 MB"));

        // Add panels to main panel
        mainPanel.add(settingsPanel, BorderLayout.NORTH);
        mainPanel.add(statusPanel, BorderLayout.CENTER);

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
        try {
            persistedData.setString("openai_key", new String(openaiKeyField.getPassword()));
            persistedData.setString("gemini_key", new String(geminiKeyField.getPassword()));
            persistedData.setString("claude_key", new String(claudeKeyField.getPassword()));
            persistedData.setString("selected_model", (String) modelDropdown.getSelectedItem());
            persistedData.setString("prompt_template", promptTemplateArea.getText());
            
            SwingUtilities.invokeLater(() -> 
                JOptionPane.showMessageDialog(mainPanel, "Settings saved successfully", 
                    "Success", JOptionPane.INFORMATION_MESSAGE));
        } catch (Exception e) {
            api.logging().logToError("Error saving settings: " + e.getMessage());
            showError("Error saving settings", e);
        }
    }

    private void loadSavedSettings() {
        if (openaiKeyField != null) {
            openaiKeyField.setText(persistedData.getString("openai_key"));
        }
        if (geminiKeyField != null) {
            geminiKeyField.setText(persistedData.getString("gemini_key"));
        }
        if (claudeKeyField != null) {
            claudeKeyField.setText(persistedData.getString("claude_key"));
        }
        if (modelDropdown != null) {
            String model = persistedData.getString("selected_model");
            if (model != null) {
                modelDropdown.setSelectedItem(model);
            }
        }
        if (promptTemplateArea != null) {
            String template = persistedData.getString("prompt_template");
            if (template != null && !template.isEmpty()) {
                promptTemplateArea.setText(template);
            } else {
                promptTemplateArea.setText(getDefaultPromptTemplate());
            }
        }
    }

    private String getDefaultPromptTemplate() {
        return "You are a web application security expert conducting a thorough security assessment. " +
               "Analyze the provided HTTP request and response for security vulnerabilities, focusing on: " +
               "1. Authentication/Authorization issues\n" +
               "2. Injection vulnerabilities (SQL, Command, etc.)\n" +
               "3. Information disclosure\n" +
               "4. Insecure configurations\n" +
               "5. Session management issues\n" +
               "6. Access control vulnerabilities\n\n" +
               "Format findings as JSON with the following structure:\n" +
               "{\n" +
               "  \"findings\": [{\n" +
               "    \"vulnerability\": \"Specific, concise title\",\n" +
               "    \"location\": \"Exact location in request/response\",\n" +
               "    \"explanation\": \"Detailed technical explanation with evidence\",\n" +
               "    \"severity\": \"HIGH|MEDIUM|LOW|INFORMATION\",\n" +
               "    \"confidence\": \"CERTAIN|FIRM|TENTATIVE\"\n" +
               "  }]\n" +
               "}";
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
                             + "    {\"parts\": [{\"text\": \"Say hi if you are there.\"}]}"
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
                             + "    {\"role\": \"user\", \"content\": \"Say hi if you are there\"}"
                             + "  ]"
                             + "}";
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
    
        if (apiKey == null || apiKey.isEmpty()) {
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
    
                // Create a Set to track processed vulnerabilities
                Set<String> processedVulnerabilities = new HashSet<>();
    
                // Submit tasks to the thread pool for analysis
                List<CompletableFuture<JSONObject>> futures = new ArrayList<>();
                for (String chunk : chunks) {
                    futures.add(threadPoolManager.submitTask(provider,
                        () -> sendToAI(selectedModel, apiKey, chunk)));
                }
    
                // Process all chunks and combine results
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
                // Google API key is included in the URL
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

        String content = null;

        // Extract response content based on the provider
        if (aiResponse.has("content")) {
            JSONArray contentArray = aiResponse.getJSONArray("content");
            if (contentArray.length() > 0) {
                content = contentArray.getJSONObject(0).getString("text");
            }
        } else if (aiResponse.has("choices")) {
            content = aiResponse
                    .getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content");
        }

        if (content == null) {
            throw new JSONException("No valid content found in AI response.");
        }

        // Log raw content
        api.logging().logToOutput("Raw content: " + content);

        // Check if the content includes findings JSON (wrapped in ```json ... ```)
        if (!content.startsWith("```json")) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "Error processing AI findings: Content is not in the expected JSON format.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            });
            return;
        }

        // Extract JSON string between the backticks
        String jsonContent = content.substring(content.indexOf("{"), content.lastIndexOf("}") + 1);

        api.logging().logToOutput("Extracted JSON: " + jsonContent);

        // Parse the JSON string
        JSONObject findingsJson = new JSONObject(jsonContent);

        // Ensure "findings" key exists
        if (!findingsJson.has("findings")) {
            api.logging().logToError("Key 'findings' not found in extracted JSON: " + findingsJson.toString(2));
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "Error processing AI findings: 'findings' not found in extracted JSON.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            });
            return;
        }

        // Parse the findings array
        JSONArray findings = findingsJson.getJSONArray("findings");

        for (int i = 0; i < findings.length(); i++) {
            JSONObject finding = findings.getJSONObject(i);

            // Skip duplicate vulnerabilities
            String hash = generateVulnerabilityHash(finding, requestResponse);
            if (processedVulnerabilities.contains(hash)) {
                continue;
            }
            processedVulnerabilities.add(hash);

            AuditIssueSeverity severity;
            switch (finding.getString("severity").toUpperCase()) {
                case "HIGH":
                    severity = AuditIssueSeverity.HIGH;
                    break;
                case "MEDIUM":
                    severity = AuditIssueSeverity.MEDIUM;
                    break;
                case "LOW":
                    severity = AuditIssueSeverity.LOW;
                    break;
                default:
                    severity = AuditIssueSeverity.INFORMATION;
                    break;
            }

            AuditIssueConfidence confidence;
            switch (finding.getString("confidence").toUpperCase()) {
                case "CERTAIN":
                    confidence = AuditIssueConfidence.CERTAIN;
                    break;
                case "FIRM":
                    confidence = AuditIssueConfidence.FIRM;
                    break;
                default:
                    confidence = AuditIssueConfidence.TENTATIVE;
                    break;
            }

            // Build issue details
            StringBuilder issueDetail = new StringBuilder();
            issueDetail.append("Issue identified by AI Auditor\n\n");
            issueDetail.append("Location: ").append(finding.getString("location")).append("\n\n");
            issueDetail.append("Detailed Explanation:\n").append(finding.getString("explanation")).append("\n\n");
            issueDetail.append("Confidence Level: ").append(finding.getString("confidence")).append("\n");
            issueDetail.append("Severity Level: ").append(finding.getString("severity"));

            // Build the AIAuditIssue using the builder
            AIAuditIssue issue = new AIAuditIssue.Builder()
                .name("AI Audit: " + finding.getString("vulnerability"))
                .detail(issueDetail.toString())
                .endpoint(requestResponse.request().url()) // Correct method to set the URL
                .severity(severity)
                .confidence(confidence)
                .requestResponses(Collections.singletonList(requestResponse))
                .modelUsed(model) // Include the model used for context
                .build();

            // Add issue to the Site Map
            api.siteMap().add(issue);
        }
    } catch (Exception e) {
        api.logging().logToError("Error processing AI findings: " + e.getMessage());
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                "Error processing AI findings: " + e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE);
        });
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
                // Extract "completion" for Claude
                return SafeUtils.safeGetString(response, "completion");

            case "gemini":
                // Extract "content" under "candidates" for Gemini
                JSONArray candidates = SafeUtils.safeGetArray(response, "candidates");
                if (candidates.length() > 0) {
                    return SafeUtils.safeGetString(candidates.getJSONObject(0), "content");
                }
                break;

            case "openai":
                // Use the original parsing logic for OpenAI
                return response
                        .getJSONArray("choices")
                        .getJSONObject(0)
                        .getJSONObject("message")
                        .getString("content");

            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    } catch (Exception e) {
        throw new RuntimeException("Failed to extract content from response: " + e.getMessage(), e);
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
            if (!new String(claudeKeyField.getPassword()).isEmpty()) return "claude-3-sonnet-latest";
            if (!new String(openaiKeyField.getPassword()).isEmpty()) return "gpt-4o"; // Set `gpt-4o` as the default OpenAI model
            if (!new String(geminiKeyField.getPassword()).isEmpty()) return "gemini-1.5-pro";
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
        // This extension doesn't implement active scanning
        return AuditResult.auditResult(Collections.emptyList());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // This extension doesn't implement passive scanning
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

