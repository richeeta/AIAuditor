package burp;

import java.io.Closeable;
import java.io.IOException;
import java.net.HttpURLConnection;

import org.json.JSONArray;
import org.json.JSONObject;

public class SafeUtils {
    public static String safeGetString(JSONObject obj, String key) {
        if (obj == null || !obj.has(key)) {
            return "";
        }
        try {
            return obj.getString(key);
        } catch (Exception e) {
            return "";
        }
    }

    public static JSONArray safeGetArray(JSONObject obj, String key) {
        if (obj == null || !obj.has(key)) {
            return new JSONArray();
        }
        try {
            return obj.getJSONArray(key);
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    public static JSONObject safeGetObject(JSONObject obj, String key) {
        if (obj == null || !obj.has(key)) {
            return new JSONObject();
        }
        try {
            return obj.getJSONObject(key);
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    public static void closeQuietly(Closeable... closeables) {
        for (Closeable closeable : closeables) {
            try {
                if (closeable != null) {
                    closeable.close();
                }
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    public static void disconnectQuietly(HttpURLConnection conn) {
        if (conn != null) {
            try {
                conn.disconnect();
            } catch (Exception e) {
                // Ignore
            }
        }
    }
}