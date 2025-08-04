package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestChunker {
    private static int MAX_TOKENS_PER_CHUNK = 8192; 

   public static void setMaxTokensPerChunk(int size) {
     MAX_TOKENS_PER_CHUNK = size;
   }
    private static final Pattern BOUNDARY_PATTERN = Pattern.compile(
        "(?<=\\n\\n)|(?=\\n\\n)|(?<=\\})|(?=\\{)|(?<=;)|(?<=\\n)|(?=\\n)"
    );

    public static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        return (int) Math.ceil(text.length() / 4.0);
    }

    public static List<String> chunkContent(String content, String prompt) {
        List<String> chunks = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return chunks;
        }

        int promptTokens = estimateTokens(prompt);
        int maxContentTokens = MAX_TOKENS_PER_CHUNK - promptTokens;

        if (maxContentTokens <= 0) {
            return chunks;
        }

        int totalContentTokens = estimateTokens(content);

        if (totalContentTokens <= maxContentTokens) {
            chunks.add(content);
            return chunks;
        }

        // Approximate character count for the max content tokens
        int maxContentChars = maxContentTokens * 4;

        // Explicit check to prevent negative or zero maxContentChars from causing issues
        if (maxContentChars <= 0) {
            return chunks;
        }

        int currentPos = 0;
        while (currentPos < content.length()) {
            int endPos = Math.min(currentPos + maxContentChars, content.length());
            chunks.add(content.substring(currentPos, endPos));
            currentPos = endPos;
        }

        return chunks;
    }

    private static List<String> splitLongString(String str) {
        List<String> chunks = new ArrayList<>();
        int length = str.length();
        for (int i = 0; i < length; i += (MAX_TOKENS_PER_CHUNK * 4)) {
            chunks.add(str.substring(i, Math.min(length, i + (MAX_TOKENS_PER_CHUNK * 4))));
        }
        return chunks;
    }

    public static String extractHighlightedPortion(String content, int selectionStart, int selectionEnd) {
        if (selectionStart < 0 || selectionEnd > content.length() || selectionStart >= selectionEnd) {
            return content;
        }

        while (selectionStart > 0 && content.charAt(selectionStart - 1) != '\n') {
            selectionStart--;
        }
        while (selectionEnd < content.length() && content.charAt(selectionEnd) != '\n') {
            selectionEnd++;
        }

        return content.substring(selectionStart, selectionEnd);
    }
}