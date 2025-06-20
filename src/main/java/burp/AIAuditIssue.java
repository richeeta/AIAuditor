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

 import java.util.Collections;
 import java.util.List;

 import burp.api.montoya.collaborator.Interaction;
 import burp.api.montoya.http.HttpService;
 import burp.api.montoya.http.message.HttpRequestResponse;
 import burp.api.montoya.scanner.audit.issues.AuditIssue;
 import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
 import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
 import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
 
 public class AIAuditIssue implements AuditIssue {
     private final String name;
     private final String detail;
     private final String endpoint;
     private final AuditIssueSeverity severity;
     private final AuditIssueConfidence confidence;
     private final List<HttpRequestResponse> requestResponses;
     private final HttpService httpService;
     private final String modelUsed;
 
     private AIAuditIssue(Builder builder) {
         this.name = builder.name;
         this.detail = formatDetail(builder.detail, builder.modelUsed);
         this.endpoint = builder.endpoint;
         this.severity = builder.severity;
         this.confidence = builder.confidence;
         this.requestResponses = builder.requestResponses;
         this.httpService = builder.requestResponses.get(0).httpService();
         this.modelUsed = builder.modelUsed;
     }
 
     private String formatDetail(String detail, String modelUsed) {
         StringBuilder formattedDetail = new StringBuilder();
         formattedDetail.append("<div style='font-family: Arial, sans-serif;'>");
         formattedDetail.append("<p><b>Scanned with:</b> ").append(modelUsed).append("</p>");
         formattedDetail.append("<hr/>");
         
         // Replace common markdown-style formatting with HTML
         String htmlDetail = detail
             .replace("**", "<b>")
             .replace("__", "<b>")
             .replace("*", "<i>")
             .replace("_", "<i>")
             .replace("\n\n", "</p><p>")
             .replace("\n", "<br/>");
         
         // Ensure all paragraphs are properly closed
         if (!htmlDetail.endsWith("</p>")) {
             htmlDetail += "</p>";
         }
         
         formattedDetail.append(htmlDetail);
         formattedDetail.append("</div>");
         
         return formattedDetail.toString();
     }
 
     @Override
     public AuditIssueDefinition definition() {
         return AuditIssueDefinition.auditIssueDefinition(
             name,
             "This issue was identified by the AI Auditor extension.",
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
 
     public static class Builder {
         private String name;
         private String detail;
         private String endpoint;
         private AuditIssueSeverity severity;
         private AuditIssueConfidence confidence;
         private List<HttpRequestResponse> requestResponses;
         private String modelUsed;
 
         public Builder name(String name) {
             this.name = name;
             return this;
         }
 
         public Builder detail(String detail) {
             this.detail = detail;
             return this;
         }
 
         public Builder endpoint(String endpoint) {
             this.endpoint = endpoint;
             return this;
         }
 
         public Builder severity(AuditIssueSeverity severity) {
             this.severity = severity;
             return this;
         }
 
         public Builder confidence(AuditIssueConfidence confidence) {
             this.confidence = confidence;
             return this;
         }
 
         public Builder requestResponses(List<HttpRequestResponse> requestResponses) {
             this.requestResponses = requestResponses;
             return this;
         }
 
         public Builder modelUsed(String modelUsed) {
             this.modelUsed = modelUsed;
             return this;
         }
 
         public AIAuditIssue build() {
             return new AIAuditIssue(this);
         }
     }
 }