package burp;

import java.io.IOException;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.List;
import org.json.JSONObject;
import org.json.JSONArray;

public class AIAuditor implements BurpExtension, ContextMenuItemsProvider, ScanCheck {
    private static final String EXTENSION_NAME = "AI Auditor";
    private MontoyaApi api;
    private PersistedObject persistedData;
    private JTextField openaiKeyField;
    private JTextField geminiKeyField;
    private JTextField claudeKeyField;
    private JComboBox<String> modelDropdown;
    private JTextField instructionsField;
    private JSpinner contextSpinner;
    private JPanel mainPanel;
    private Registration menuRegistration;
    private Registration scanCheckRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.persistedData = api.persistence().extensionData();
        
        // Register extension capabilities
        api.extension().setName(EXTENSION_NAME);
        menuRegistration = api.userInterface().registerContextMenuItemsProvider(this);
        scanCheckRegistration = api.scanner().registerScanCheck(this);
        
        createMainTab();
        loadSavedSettings();
    }

    private void createMainTab() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // API Keys Panel
        JPanel apiPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // OpenAI
        gbc.gridx = 0; gbc.gridy = 0;
        apiPanel.add(new JLabel("OpenAI API Key:"), gbc);
        openaiKeyField = new JPasswordField(40);
        openaiKeyField.setText(persistedData.getString("openai_key"));
        gbc.gridx = 1;
        apiPanel.add(openaiKeyField, gbc);
        JButton validateOpenAI = new JButton("Validate");
        validateOpenAI.addActionListener(e -> validateApiKey("openai"));
        gbc.gridx = 2;
        apiPanel.add(validateOpenAI, gbc);

        // Gemini
        gbc.gridx = 0; gbc.gridy = 1;
        apiPanel.add(new JLabel("Gemini API Key:"), gbc);
        geminiKeyField = new JPasswordField(40);
        geminiKeyField.setText(persistedData.getString("gemini_key"));
        gbc.gridx = 1;
        apiPanel.add(geminiKeyField, gbc);
        JButton validateGemini = new JButton("Validate");
        validateGemini.addActionListener(e -> validateApiKey("gemini"));
        gbc.gridx = 2;
        apiPanel.add(validateGemini, gbc);

        // Claude
        gbc.gridx = 0; gbc.gridy = 2;
        apiPanel.add(new JLabel("Claude API Key:"), gbc);
        claudeKeyField = new JPasswordField(40);
        claudeKeyField.setText(persistedData.getString("claude_key"));
        gbc.gridx = 1;
        apiPanel.add(claudeKeyField, gbc);
        JButton validateClaude = new JButton("Validate");
        validateClaude.addActionListener(e -> validateApiKey("claude"));
        gbc.gridx = 2;
        apiPanel.add(validateClaude, gbc);

        // Model Selection
        gbc.gridx = 0; gbc.gridy = 3;
        apiPanel.add(new JLabel("AI Model:"), gbc);
        modelDropdown = new JComboBox<>(new String[]{"Default", "o1-preview", "o1-mini", "gpt-4o", "gpt-4o-mini", "gemini-1.5-pro", "claude-3.5-sonnet"});
        String savedModel = persistedData.getString("selected_model");
        if (savedModel != null) {
            modelDropdown.setSelectedItem(savedModel);
        }
        gbc.gridx = 1;
        apiPanel.add(modelDropdown, gbc);

        // Custom Instructions
        gbc.gridx = 0; gbc.gridy = 4;
        apiPanel.add(new JLabel("Custom Instructions:"), gbc);
        instructionsField = new JTextField(40);
        instructionsField.setText(persistedData.getString("custom_instructions"));
        gbc.gridx = 1;
        apiPanel.add(instructionsField, gbc);

        // Context Number
        gbc.gridx = 0; gbc.gridy = 5;
        apiPanel.add(new JLabel("Context Number (0-5):"), gbc);
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(1, 0, 5, 1);
        contextSpinner = new JSpinner(spinnerModel);
        Integer savedContext = persistedData.getInteger("context_number");
        if (savedContext != null) {
            contextSpinner.setValue(savedContext);
        }
        gbc.gridx = 1;
        apiPanel.add(contextSpinner, gbc);

        // Save Button
        JButton saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        gbc.gridx = 1; gbc.gridy = 6;
        apiPanel.add(saveButton, gbc);

        mainPanel.add(apiPanel);

        // Register the tab
        api.userInterface().registerSuiteTab("AI Auditor", mainPanel);
    }

    private void saveSettings() {
        persistedData.setString("openai_key", openaiKeyField.getText());
        persistedData.setString("gemini_key", geminiKeyField.getText());
        persistedData.setString("claude_key", claudeKeyField.getText());
        persistedData.setString("selected_model", (String) modelDropdown.getSelectedItem());
        persistedData.setString("custom_instructions", instructionsField.getText());
        persistedData.setInteger("context_number", (Integer) contextSpinner.getValue());
    }

    private void loadSavedSettings() {
        if (openaiKeyField != null) openaiKeyField.setText(persistedData.getString("openai_key"));
        if (geminiKeyField != null) geminiKeyField.setText(persistedData.getString("gemini_key"));
        if (claudeKeyField != null) claudeKeyField.setText(persistedData.getString("claude_key"));
        if (modelDropdown != null) {
            String model = persistedData.getString("selected_model");
            if (model != null) modelDropdown.setSelectedItem(model);
        }
        if (instructionsField != null) instructionsField.setText(persistedData.getString("custom_instructions"));
        if (contextSpinner != null) {
            Integer context = persistedData.getInteger("context_number");
            if (context != null) contextSpinner.setValue(context);
        }
    }

    private void validateApiKey(String provider) {
        String key = "";
        switch (provider) {
            case "openai":
                key = openaiKeyField.getText();
                break;
            case "gemini":
                key = geminiKeyField.getText();
                break;
            case "claude":
                key = claudeKeyField.getText();
                break;
        }

        boolean isValid = validateKey(provider, key);
        String message = isValid ? "API key is valid" : "API key validation failed";
        JOptionPane.showMessageDialog(mainPanel, message);
    }

    private boolean validateKey(String provider, String key) {
    String jsonBody = "";
    String endpoint = "";

    try {
        // Set endpoint and payload based on provider
        switch (provider) {
            case "openai":
                endpoint = "https://api.openai.com/v1/models";
                break;

            case "gemini":
                endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + key;
                jsonBody = "{\"contents\":[{\"parts\":[{\"text\":\"Random word.\"}]}]}";
                break;

            case "claude":
                endpoint = "https://api.anthropic.com/v1/messages";
                jsonBody = "{\"model\":\"claude-3-5-sonnet-20241022\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"validate\"}]}";
                break;

            default:
                return false;
        }

        // Open connection
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestMethod(provider.equals("claude") || provider.equals("gemini") ? "POST" : "GET");

        // Add provider-specific headers
        if (provider.equals("openai")) {
            conn.setRequestProperty("Authorization", "Bearer " + key);
        } else if (provider.equals("claude")) {
            conn.setRequestProperty("x-api-key", key);
            conn.setRequestProperty("anthropic-version", "2023-06-01");
        }

        // Send request body if necessary
        if (!jsonBody.isEmpty()) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes("UTF-8"));
                os.flush();
            }
        }

        // Handle response
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            StringBuilder errorResponse = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    errorResponse.append(line);
                }
            }
            api.logging().logToError("Validation failed with response: " + errorResponse.toString());
            return false;
        }
        return true;

    } catch (Exception e) {
        api.logging().logToError("API validation error: " + e.getMessage());
        return false;
    }
}


@Override
public List<Component> provideMenuItems(ContextMenuEvent event) {
    // Fix to handle both message editor and proxy history
    Optional<MessageEditorHttpRequestResponse> messageEditorReqRes = event.messageEditorRequestResponse();
    
    if (messageEditorReqRes.isPresent() || !event.selectedRequestResponses().isEmpty()) {
        JMenuItem menuItem = new JMenuItem("AI Audit/Scan");
        menuItem.addActionListener(e -> processSelectedMessages(event)); // Pass the event directly
        return Collections.singletonList(menuItem);
    }
    return Collections.emptyList();
}

private void processSelectedMessages(ContextMenuEvent event) {
    Optional<MessageEditorHttpRequestResponse> messageInfo = event.messageEditorRequestResponse();
    if (!messageInfo.isPresent()) {
        return;
    }

    HttpRequestResponse requestResponse = messageInfo.get().requestResponse();
    analyzeRequestResponse(requestResponse);
}    

    private void analyzeRequestResponse(HttpRequestResponse requestResponse) {
        String selectedModel = getSelectedModel();
        String apiKey = getApiKeyForModel(selectedModel);
        
        if (apiKey == null || apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "API key not configured for selected model");
            return;
        }

        try {
            String request = requestResponse.request().toString();
            String response = requestResponse.response() != null ? requestResponse.response().toString() : "";
            
            JSONObject analysisResult = sendToAI(selectedModel, apiKey, request, response);
            if (analysisResult != null) {
                processAIFindings(analysisResult, requestResponse);
            }
        } catch (Exception e) {
            api.logging().logToError("Error analyzing request/response: " + e.getMessage());
            api.logging().logToError(e);
        }
    }

    private String getSelectedModel() {
        String model = (String) modelDropdown.getSelectedItem();
        if ("Default".equals(model)) {
            if (!openaiKeyField.getText().isEmpty()) return "gpt-4o";
            if (!geminiKeyField.getText().isEmpty()) return "gemini-1.5-pro";
            if (!claudeKeyField.getText().isEmpty()) return "claude-3.5-sonnet";
        }
        return model;
    }

    private String getApiKeyForModel(String model) {
        if (model.startsWith("gpt") || model.startsWith("o1")) return openaiKeyField.getText();
        if (model.startsWith("gemini")) return geminiKeyField.getText();
        if (model.startsWith("claude")) return claudeKeyField.getText();
        return null;
    }

private JSONObject sendToAI(String model, String apiKey, String request, String response) {
    try {
        URL url;
        JSONObject jsonBody = new JSONObject();

        // Define the prompt
        String prompt = "You are a web application security expert conducting a thorough security assessment. " +
                "Analyze the provided HTTP request and response for security vulnerabilities, focusing on: " +
                "1. Authentication/Authorization issues " +
                "2. Injection vulnerabilities (SQL, Command, etc.) " +
                "3. Information disclosure " +
                "4. Insecure configurations " +
                "5. Session management issues " +
                "6. Hardcoded secrets/credentials " +
                "7. Access control issues " +
                "\n\nProvide findings ONLY if there is clear evidence in the request/response. " +
                "Do not report theoretical issues without supporting evidence. " +
                "Rate confidence as: " +
                "CERTAIN: Clear evidence in request/response " +
                "FIRM: Strong indicators but needs validation " +
                "TENTATIVE: Potential issue requiring further investigation " +
                "\n\nFormat each finding as JSON: {\"findings\": [{" +
                "\"vulnerability\": \"Specific, concise title\", " +
                "\"location\": \"Exact location in request/response\", " +
                "\"explanation\": \"Detailed technical explanation with evidence\", " +
                "\"exploitation\": \"Specific steps to exploit\", " +
                "\"validation_steps\": \"Concrete steps to validate/reproduce\", " +
                "\"confidence\": \"CERTAIN|FIRM|TENTATIVE\", " +
                "\"severity\": \"HIGH|MEDIUM|LOW|INFORMATION\"}]}";

        String customInstructions = instructionsField.getText();
        if (!customInstructions.isEmpty()) {
            prompt = customInstructions + "\n" + prompt;
        }

        // Escape and sanitize input
        request = sanitizeInput(request);
        response = sanitizeInput(response);

        // Construct JSON payload based on the selected model
        if (model.startsWith("gpt") || model.startsWith("o1")) { // OpenAI
            url = new URL("https://api.openai.com/v1/chat/completions");

            jsonBody.put("model", model);
            JSONArray messages = new JSONArray();
            JSONObject message = new JSONObject();
            message.put("role", "user");
            message.put("content", String.format("%s\n\nRequest:\n%s\n\nResponse:\n%s", prompt, request, response));
            messages.put(message);
            jsonBody.put("messages", messages);

        } else if (model.startsWith("gemini")) { // Google Gemini
            url = new URL("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey);

            jsonBody.put("contents", new JSONArray()
                    .put(new JSONObject()
                            .put("parts", new JSONArray()
                                    .put(new JSONObject()
                                            .put("text", String.format("%s\n\nRequest:\n%s\n\nResponse:\n%s", prompt, request, response))))));

        } else if (model.startsWith("claude")) { // Anthropic Claude
            url = new URL("https://api.anthropic.com/v1/messages");

            jsonBody.put("model", model);
            jsonBody.put("max_tokens", 4000);
            jsonBody.put("messages", new JSONArray()
                    .put(new JSONObject()
                            .put("role", "user")
                            .put("content", String.format("%s\n\nRequest:\n%s\n\nResponse:\n%s", prompt, request, response))));

        } else {
            throw new IllegalArgumentException("Unsupported model: " + model);
        }

        // Log the JSON payload for debugging
        api.logging().logToOutput("Sending JSON payload to " + url + ":\n" + jsonBody.toString(2));

        // Open connection
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        // Add provider-specific headers
        if (model.startsWith("gpt") || model.startsWith("o1")) { // OpenAI
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
        } else if (model.startsWith("claude")) { // Claude
            conn.setRequestProperty("x-api-key", apiKey);
            conn.setRequestProperty("anthropic-version", "2023-06-01");
        }

        // Send the request body
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.toString().getBytes("UTF-8"));
            os.flush();
        }

        // Handle the response
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            // Read error response
            StringBuilder errorResponse = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    errorResponse.append(line);
                }
            }
            api.logging().logToError("Error response from AI: " + errorResponse.toString());
            throw new IOException("API responded with error code: " + responseCode);
        }

        // Read successful response
        StringBuilder responseBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                responseBuilder.append(line);
            }
        }

        // Parse and return the JSON response
        return new JSONObject(responseBuilder.toString());

    } catch (Exception e) {
        api.logging().logToError("Error sending request to AI: " + e.getMessage());
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                    "Error sending request to AI: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        });
        return null;
    }
}

/**
 * Sanitizes input by escaping special characters to make it JSON-safe.
 */
private String sanitizeInput(String input) {
    return input.replace("\\", "\\\\")  // Escape backslashes
                .replace("\"", "\\\"")  // Escape double quotes
                .replace("\n", "\\n")  // Escape newlines
                .replace("\r", "\\r")  // Escape carriage returns
                .replace("\t", "\\t"); // Escape tabs
}






  private void processAIFindings(JSONObject aiResponse, HttpRequestResponse requestResponse) {
    try {
        // Log the AI response for debugging
        api.logging().logToOutput("AI Response: " + aiResponse.toString(2));

        // Extract the "content" field from the assistant's message
        String content = aiResponse
            .getJSONArray("choices")
            .getJSONObject(0)
            .getJSONObject("message")
            .getString("content");

        api.logging().logToOutput("Raw content: " + content);

        // Check if content includes the findings JSON (wrapped in ```json ... ```)
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

        // Check if "findings" key exists
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

            // Build the issue details
            StringBuilder issueDetail = new StringBuilder();
            issueDetail.append("Issue identified by AI Auditor\n\n");
            issueDetail.append("Location: ").append(finding.getString("location")).append("\n\n");
            issueDetail.append("Detailed Explanation:\n").append(finding.getString("explanation")).append("\n\n");
            issueDetail.append("Exploitation Method:\n").append(finding.getString("exploitation")).append("\n\n");
            issueDetail.append("Validation Steps:\n").append(finding.getString("validation_steps")).append("\n\n");
            issueDetail.append("Confidence Level: ").append(finding.getString("confidence")).append("\n");
            issueDetail.append("Severity Level: ").append(finding.getString("severity"));

            // Create and add the audit issue
            AIAuditIssue issue = new AIAuditIssue(
                "AI Audit: " + finding.getString("vulnerability"),
                issueDetail.toString(),
                requestResponse.request().url(),
                severity,
                confidence,
                Collections.singletonList(requestResponse)
            );

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
        // Compare issues to determine if they are duplicates
        if (newIssue.name().equals(existingIssue.name()) &&
            newIssue.detail().equals(existingIssue.detail()) &&
            newIssue.severity().equals(existingIssue.severity())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}