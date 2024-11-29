package com.richeeta;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.menu.MenuItem;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

public class AIAuditor implements BurpExtension, ScanCheck {

    private MontoyaApi api;
    private JTextField apiKeyField;
    private JComboBox<String> modelSelector;
    private JSpinner maxRequestsSpinner;
    private JCheckBox includeContextCheckbox;
    private JTextArea instructionsArea;
    private String savedApiKey;
    private String selectedModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Auditor");

        // Create UI components
        createUI();

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(this::getContextMenuItems);

        // Register as a scanner check
        api.scanner().registerScanCheck(this);
    }

    private void createUI() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);

        // API Key input
        mainPanel.add(new JLabel("OpenAI API Key:"), gbc);
        gbc.gridx++;
        apiKeyField = new JTextField(30);
        mainPanel.add(apiKeyField, gbc);

        // Model selection
        gbc.gridx = 0;
        gbc.gridy++;
        mainPanel.add(new JLabel("OpenAI Model:"), gbc);
        gbc.gridx++;
        modelSelector = new JComboBox<>(new String[]{"o1-preview", "o1-mini", "GPT-4", "GPT-4o", "GPT-4o-mini"});
        modelSelector.setSelectedItem("GPT-4o");
        mainPanel.add(modelSelector, gbc);

        // Max requests per analysis
        gbc.gridx = 0;
        gbc.gridy++;
        mainPanel.add(new JLabel("Max Requests per Analysis:"), gbc);
        gbc.gridx++;
        maxRequestsSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
        mainPanel.add(maxRequestsSpinner, gbc);

        // Include context checkbox
        gbc.gridx = 0;
        gbc.gridy++;
        includeContextCheckbox = new JCheckBox("Include Context in Analysis");
        mainPanel.add(includeContextCheckbox, gbc);

        // Instructions text area
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        mainPanel.add(new JLabel("Customizable Analysis Instructions:"), gbc);
        gbc.gridy++;
        instructionsArea = new JTextArea(10, 40);
        instructionsArea.setLineWrap(true);
        instructionsArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(instructionsArea);
        mainPanel.add(scrollPane, gbc);

        // Save button
        gbc.gridy++;
        JButton saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        mainPanel.add(saveButton, gbc);

        // Add the main panel to Burp's UI
        api.userInterface().registerSuiteTab("AI Auditor", mainPanel);

        // Load saved settings
        loadSettings();
    }

    private void saveSettings() {
        savedApiKey = apiKeyField.getText();
        selectedModel = (String) modelSelector.getSelectedItem();
        api.persistence().preferences().setString("ai_auditor_api_key", savedApiKey);
        api.persistence().preferences().setString("ai_auditor_model", selectedModel);
        api.persistence().preferences().setInt("ai_auditor_max_requests", (Integer) maxRequestsSpinner.getValue());
        api.persistence().preferences().setBoolean("ai_auditor_include_context", includeContextCheckbox.isSelected());
        api.persistence().preferences().setString("ai_auditor_instructions", instructionsArea.getText());
        api.logging().logToOutput("AI Auditor settings saved.");
    }

    private void loadSettings() {
        savedApiKey = api.persistence().preferences().getString("ai_auditor_api_key");
        selectedModel = api.persistence().preferences().getString("ai_auditor_model");
        apiKeyField.setText(savedApiKey);
        modelSelector.setSelectedItem(selectedModel != null ? selectedModel : "GPT-4o");
        maxRequestsSpinner.setValue(api.persistence().preferences().getInt("ai_auditor_max_requests", 5));
        includeContextCheckbox.setSelected(api.persistence().preferences().getBoolean("ai_auditor_include_context", false));
        instructionsArea.setText(api.persistence().preferences().getString("ai_auditor_instructions", ""));
    }

    private List<MenuItem> getContextMenuItems(UserInterface userInterface) {
        List<MenuItem> menuItems = new ArrayList<>();
        menuItems.add(MenuItem.builder()
                .action(context -> analyzeSelectedMessages(context.selectedRequestResponses()))
                .title("Scan with AI Auditor")
                .build());
        return menuItems;
    }

    private void analyzeSelectedMessages(List<HttpRequestResponse> selectedMessages) {
        if (savedApiKey == null || savedApiKey.isEmpty()) {
            api.logging().logToError("OpenAI API key not set. Please configure it in the AI Auditor tab.");
            return;
        }

        int maxRequests = (Integer) maxRequestsSpinner.getValue();
        List<HttpRequestResponse> messagesToAnalyze = selectedMessages.subList(0, Math.min(selectedMessages.size(), maxRequests));

        StringBuilder requestsJson = new StringBuilder("[");
        for (HttpRequestResponse message : messagesToAnalyze) {
            requestsJson.append("{\"request\":\"").append(escapeJson(message.request().toString())).append("\",");
            requestsJson.append("\"response\":\"").append(escapeJson(message.response().toString())).append("\"},");
        }
        requestsJson.setCharAt(requestsJson.length() - 1, ']');

        String prompt = instructionsArea.getText().isEmpty() ? getDefaultPrompt() : instructionsArea.getText();
        String jsonBody = String.format("{\"model\": \"%s\", \"messages\": [{\"role\": \"system\", \"content\": %s}, {\"role\": \"user\", \"content\": \"Analyze these HTTP requests and responses: %s\"}]}",
                selectedModel, new Gson().toJson(prompt), requestsJson.toString());

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + savedApiKey)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            processAIResponse(response.body(), messagesToAnalyze.get(0));
        } catch (IOException | InterruptedException e) {
            api.logging().logToError("Error sending request to OpenAI API: " + e.getMessage());
        }
    }

    private String escapeJson(String input) {
        return input.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void processAIResponse(String aiResponse, HttpRequestResponse originalMessage) {
        JsonObject jsonResponse = new Gson().fromJson(aiResponse, JsonObject.class);
        JsonArray choices = jsonResponse.getAsJsonArray("choices");
        if (choices != null && choices.size() > 0) {
            JsonObject messageContent = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            String content = messageContent.get("content").getAsString();
            JsonObject findings = new Gson().fromJson(content, JsonObject.class);
            JsonArray findingsArray = findings.getAsJsonArray("findings");

            for (int i = 0; i < findingsArray.size(); i++) {
                JsonObject finding = findingsArray.get(i).getAsJsonObject();
                String title = finding.get("title").getAsString();
                String severity = finding.get("severity").getAsString();
                int confidence = finding.get("confidence").getAsInt();
                String details = finding.get("details").getAsString();
                String impact = finding.get("impact").getAsString();
                String remediation = finding.get("remediation").getAsString();

                AuditResult auditResult = AuditResult.auditResult(title)
                        .severity(convertSeverity(severity))
                        .confidence(convertConfidence(confidence))
                        .detail(details)
                        .remediationDetail(remediation)
                        .build();

                api.scanner().addScanIssue(auditResult);
            }
        }
    }

    private AuditResult.Severity convertSeverity(String severity) {
        switch (severity.toLowerCase()) {
            case "critical":
                return AuditResult.Severity.HIGH;
            case "high":
                return AuditResult.Severity.HIGH;
            case "medium":
                return AuditResult.Severity.MEDIUM;
            case "low":
                return AuditResult.Severity.LOW;
            default:
                return AuditResult.Severity.INFORMATION;
        }
    }

    private AuditResult.Confidence convertConfidence(int confidence) {
        if (confidence >= 80) {
            return AuditResult.Confidence.FIRM;
        } else if (confidence >= 50) {
            return AuditResult.Confidence.TENTATIVE;
        } else {
            return AuditResult.Confidence.CERTAIN;
        }
    }

    private String getDefaultPrompt() {
        return "";
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse requestResponse) {
        // This method is called during active scanning
        // For this extension, we'll return null as we're not implementing active scanning
        return null;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse requestResponse) {
        // This method is called during passive scanning
        // For this extension, we'll return null as we're not implementing passive scanning
        return null;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditResult existingIssue, AuditResult newIssue) {
        // This method is called to determine how to consolidate duplicate issues
        // For simplicity, we'll always keep the existing issue
        return ConsolidationAction.KEEP_EXISTING;
    }
}

