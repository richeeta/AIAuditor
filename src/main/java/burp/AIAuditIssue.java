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
 import java.util.regex.Pattern;
 import java.util.regex.Matcher;
	
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
 


	private static final Pattern MD_BOLD   =
			Pattern.compile("(?:\\*\\*|__)(.+?)(?:\\*\\*|__)");
	private static final Pattern MD_ITALIC =
			Pattern.compile("(?<!\\*)\\*(?!\\*)(.+?)(?<!\\*)\\*(?!\\*)"  // *italic*
						  + "|_(.+?)_");                                 // _italic_
	private static final Pattern PARA      = Pattern.compile("\\n{2,}"); // blank line
	private static final Pattern BR        = Pattern.compile("\\n");     // single \n
	private static final Pattern AMP_LT    = Pattern.compile("&|<");     // escape &, <


     private AIAuditIssue(Builder builder) {
        this.name = builder.name;
		this.detail = formatDetail(builder.detail, builder.modelUsed);
		this.endpoint = builder.endpoint;
		this.severity = builder.severity;
		this.confidence = builder.confidence;

		if (builder.requestResponses == null || builder.requestResponses.isEmpty()) {
			// Fallback: keep Burp alive but the issue will not show a request tab
			this.requestResponses = Collections.emptyList();
			this.httpService      = null;
		} else {
			this.requestResponses = builder.requestResponses;
			this.httpService      = builder.requestResponses.get(0).httpService();
		}

		this.modelUsed = builder.modelUsed;
     }
 
 
	/** Converts a limited Markdown subset (bold, italic, newlines) to HTML. */
	private static String mdToHtmlLite(String md) {
		// 0️⃣ Escape raw & and < so user text can’t break our tags
		String html = AMP_LT.matcher(md)
							.replaceAll(m -> m.group().equals("&") ? "&amp;" : "&lt;");

		// 1️⃣ Bold: **text** or __text__
		html = MD_BOLD.matcher(html).replaceAll("<b>$1</b>");

		// 2️⃣ Italic: *text* or _text_
		html = MD_ITALIC.matcher(html).replaceAll("<i>$1$2</i>");

		// 3️⃣ Paragraphs and line breaks
		html = PARA.matcher(html).replaceAll("</p><p>");
		html = BR.matcher(html).replaceAll("<br/>");

		return html;
	}

	private String formatDetail(String markdownDetail, String modelUsed) {
		StringBuilder out = new StringBuilder(markdownDetail.length() + 256);

		out.append("<div style='font-family: Arial, sans-serif;'>")
		   .append("<p><b>Scanned with:</b> ")
		   .append(modelUsed)
		   .append("</p>");

		// Convert limited Markdown to HTML
		out.append("<p>")
		   .append(mdToHtmlLite(markdownDetail).trim());

		// Ensure closing tags
		if (!markdownDetail.endsWith("\n\n")) {
			out.append("</p>");
		}
		out.append("</div>");

		return out.toString();
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