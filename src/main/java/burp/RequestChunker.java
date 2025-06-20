package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestChunker {
    private static final int MAX_CHUNK_SIZE = 16384; // Increased from 8KB chunks - Feature to add input box for custom values
    private static final Pattern BOUNDARY_PATTERN = Pattern.compile(
        "(?<=\\n\\n)|(?=\\n\\n)|(?<=\\})|(?=\\{)|(?<=;)|(?<=\\n)|(?=\\n)"
    );

    public static List<String> chunkContent(String content) {
        List<String> chunks = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return chunks;
        }

        // If content is small enough, return it as a single chunk
        if (content.length() <= MAX_CHUNK_SIZE) {
            chunks.add(content);
            return chunks;
        }

        // Split content at logical boundaries
        Matcher matcher = BOUNDARY_PATTERN.matcher(content);
        int lastEnd = 0;
        StringBuilder currentChunk = new StringBuilder();

        while (matcher.find()) {
            String piece = content.substring(lastEnd, matcher.start());
            if (currentChunk.length() + piece.length() > MAX_CHUNK_SIZE) {
                // Current chunk would exceed max size, save it and start new chunk
                if (currentChunk.length() > 0) {
                    chunks.add(currentChunk.toString());
                    currentChunk = new StringBuilder();
                }
                // If piece itself is larger than max size, split it
                if (piece.length() > MAX_CHUNK_SIZE) {
                    chunks.addAll(splitLongString(piece));
                } else {
                    currentChunk.append(piece);
                }
            } else {
                currentChunk.append(piece);
            }
            lastEnd = matcher.end();
        }

        // Add final piece
        String finalPiece = content.substring(lastEnd);
        if (currentChunk.length() + finalPiece.length() <= MAX_CHUNK_SIZE) {
            currentChunk.append(finalPiece);
            chunks.add(currentChunk.toString());
        } else {
            if (currentChunk.length() > 0) {
                chunks.add(currentChunk.toString());
            }
            chunks.addAll(splitLongString(finalPiece));
        }

        return chunks;
    }

    private static List<String> splitLongString(String str) {
        List<String> chunks = new ArrayList<>();
        int length = str.length();
        for (int i = 0; i < length; i += MAX_CHUNK_SIZE) {
            chunks.add(str.substring(i, Math.min(length, i + MAX_CHUNK_SIZE)));
        }
        return chunks;
    }

    public static String extractHighlightedPortion(String content, int selectionStart, int selectionEnd) {
        if (selectionStart < 0 || selectionEnd > content.length() || selectionStart >= selectionEnd) {
            return content;
        }

        // Expand selection to include complete lines
        while (selectionStart > 0 && content.charAt(selectionStart - 1) != '\n') {
            selectionStart--;
        }
        while (selectionEnd < content.length() && content.charAt(selectionEnd) != '\n') {
            selectionEnd++;
        }

        return content.substring(selectionStart, selectionEnd);
    }
}