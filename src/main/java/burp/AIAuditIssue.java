/*
 * AIAuditIssue.java
 * Author: Richard Hyunho Im (@richeeta), Route Zero Security
 * 
 * Represents individual security findings identified by the AI Auditor.
 * This class encapsulates details such as the vulnerability type, location,
 * confidence level, severity, and actionable recommendations, making them 
 * compatible with Burp Suite’s issue tracking framework.
 * 
 * Version: 1.0
 * 
 * Date: November 28, 2024
 */

package burp;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.util.Collections;
import java.util.List;

public class AIAuditIssue implements AuditIssue {
    private final String name;
    private final String detail;
    private final String endpoint;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final List<HttpRequestResponse> requestResponses;
    private final HttpService httpService;

    public AIAuditIssue(String name, String detail, String endpoint, AuditIssueSeverity severity, 
                      AuditIssueConfidence confidence, List<HttpRequestResponse> requestResponses) {
        this.name = name;
        this.detail = detail;
        this.endpoint = endpoint;
        this.severity = severity;
        this.confidence = confidence;
        this.requestResponses = requestResponses;
        this.httpService = requestResponses.get(0).httpService();
    }

    @Override
    public AuditIssueDefinition definition() {
        return AuditIssueDefinition.auditIssueDefinition(
            name,
            "This issue was identified by the AI Auditor extension using machine learning models.",
            "Review the AI-generated findings and validate the identified issues.",
            severity
        );
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String detail() {
        return detail;
    }

    @Override
    public String remediation() {
        return "Review the AI-generated findings and validate the identified issues.";
    }

 //   @Override
    public String background() {
        return "This issue was identified by the AI Auditor extension using machine learning models.";
    }

    @Override
    public AuditIssueSeverity severity() {
        return severity;
    }

    @Override
    public AuditIssueConfidence confidence() {
        return confidence;
    }

    @Override
    public List<HttpRequestResponse> requestResponses() {
        return requestResponses;
    }

    @Override
    public String baseUrl() {
        return endpoint;
    }

    @Override
    public HttpService httpService() {
        return httpService;
    }

    @Override
    public List<Interaction> collaboratorInteractions() {
        return Collections.emptyList();
    }
}