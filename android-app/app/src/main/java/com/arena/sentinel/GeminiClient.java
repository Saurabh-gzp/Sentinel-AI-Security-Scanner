package com.arena.sentinel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

class GeminiClient {

    private static final String BASE = "https://generativelanguage.googleapis.com/v1beta";

    static class ModelInfo {
        final String id;       // "models/gemini-2.5-flash"
        final String name;     // "Gemini 2.5 Flash"
        ModelInfo(String id, String name) { this.id = id; this.name = name; }
        public String toString() { return name; }
    }

    /** Quick key validity check via the models list (used once per key). */
    static boolean validateKey(String key) {
        try {
            return !listModels(key).isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /** Fetch live models, keep only text-analysis capable + latest, max 5. */
    static List<ModelInfo> listModels(String key) throws Exception {
        String json = Net.get(BASE + "/models?key=" + enc(key));
        JSONObject root = new JSONObject(json);
        JSONArray arr = root.optJSONArray("models");
        List<ModelInfo> all = new ArrayList<>();
        if (arr == null) return all;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject m = arr.getJSONObject(i);
            String id = m.optString("name");
            String disp = m.optString("displayName", id);
            JSONArray meth = m.optJSONArray("supportedGenerationMethods");
            if (!supportsGenerate(meth)) continue;
            if (isExcluded(id)) continue;
            all.add(new ModelInfo(id, disp));
        }
        // newest first, prefer free flash/lite over pro, then alphabetical
        Collections.sort(all, new Comparator<ModelInfo>() {
            public int compare(ModelInfo a, ModelInfo b) {
                int sa = score(a.id), sb = score(b.id);
                if (sa != sb) return Integer.compare(sb, sa);
                boolean fa = isFreeFriendly(a.id), fb = isFreeFriendly(b.id);
                if (fa != fb) return fa ? -1 : 1;
                return a.id.compareTo(b.id);
            }
        });
        List<ModelInfo> out = new ArrayList<>();
        for (ModelInfo mi : all) {
            if (out.size() >= 5) break;
            out.add(mi);
        }
        return out;
    }

    private static boolean supportsGenerate(JSONArray meth) {
        if (meth == null) return false;
        for (int i = 0; i < meth.length(); i++) {
            if ("generateContent".equals(meth.optString(i))) return true;
        }
        return false;
    }

    private static boolean isExcluded(String id) {
        String l = id.toLowerCase();
        String[] bad = {"tts", "image", "nano-banana", "lyria", "robotics",
                "computer-use", "deep-research", "antigravity", "omni",
                "embedding", "aqa", "speech"};
        for (String b : bad) if (l.contains(b)) return true;
        return false;
    }

    private static boolean isFreeFriendly(String id) {
        String l = id.toLowerCase();
        return l.contains("flash") || l.contains("lite") || l.contains("gemma");
    }

    private static int score(String id) {
        String l = id.toLowerCase();
        if (l.contains("3.7")) return 370;
        if (l.contains("3.6")) return 360;
        if (l.contains("3.5")) return 350;
        if (l.contains("3.1")) return 310;
        if (l.contains("3.0") || l.contains("gemini-3-")) return 300;
        if (l.contains("2.5")) return 250;
        if (l.contains("gemma-4")) return 240;
        if (l.contains("latest")) return 200;
        return 100;
    }

    /** Generate text from a prompt; returns the concatenated model text. */
    static String generate(String key, String modelId, String prompt) throws Exception {
        return generate(key, modelId, prompt, null);
    }

    /** Vision if the model supports it; if not (e.g. text-only Gemma), automatically fall back to text-only. */
    static String generateAuto(String key, String modelId, String prompt, byte[] image) throws Exception {
        if (image == null || image.length == 0) return generate(key, modelId, prompt, null);
        try {
            return generate(key, modelId, prompt, image);
        } catch (Exception withImage) {
            try {
                return generate(key, modelId, prompt, null);
            } catch (Exception withoutImage) {
                throw withImage;
            }
        }
    }

    static void streamGenerate(String key, String modelId, String prompt, Net.TextCallback callback) throws Exception {
        String url = BASE + "/" + modelId + ":streamGenerateContent?alt=sse&key=" + enc(key);
        String body = "{\"contents\":[{\"parts\":[{\"text\":" + quote(prompt) + "}]}],"
                + "\"generationConfig\":{\"temperature\":0.2,\"maxOutputTokens\":700}}";
        Net.streamPost(url, body, callback);
    }

    /** One step of a function-calling agent loop. Returns the full JSON response (caller extracts parts). */
    static org.json.JSONObject toolCall(String key, String modelId, String systemInstruction,
                                        org.json.JSONArray contents, org.json.JSONArray tools) throws Exception {
        org.json.JSONObject body = new org.json.JSONObject();
        if (systemInstruction != null && !systemInstruction.isEmpty()) {
            body.put("systemInstruction", new org.json.JSONObject()
                    .put("parts", new org.json.JSONArray().put(new org.json.JSONObject().put("text", systemInstruction))));
        }
        body.put("contents", contents);
        if (tools != null)
            body.put("tools", new org.json.JSONArray().put(new org.json.JSONObject().put("function_declarations", tools)));
        body.put("toolConfig", new org.json.JSONObject().put("function_calling_config", new org.json.JSONObject().put("mode", "AUTO")));
        String resp = Net.post(BASE + "/" + modelId + ":generateContent?key=" + enc(key), body.toString());
        return new org.json.JSONObject(resp);
    }

    /** Extract the model parts array from a toolCall response (empty array on any issue). */
    static org.json.JSONArray partsOf(org.json.JSONObject resp) {
        try {
            return resp.getJSONArray("candidates").getJSONObject(0).getJSONObject("content").getJSONArray("parts");
        } catch (Exception e) {
            return new org.json.JSONArray();
        }
    }

    /** Generate with an optional image (Gemini vision). */
    static String generate(String key, String modelId, String prompt, byte[] image) throws Exception {
        String url = BASE + "/" + modelId + ":generateContent?key=" + enc(key);
        StringBuilder parts = new StringBuilder();
        parts.append("{\"text\":").append(quote(prompt)).append("}");
        if (image != null && image.length > 0) {
            String b64 = android.util.Base64.encodeToString(image, android.util.Base64.NO_WRAP);
            parts.append(",{\"inline_data\":{\"mime_type\":\"image/jpeg\",\"data\":\"")
                    .append(b64).append("\"}}");
        }
        String body = "{\"contents\":[{\"parts\":[" + parts + "]}],"
                + "\"generationConfig\":{\"temperature\":0.2,\"responseMimeType\":\"application/json\"}}";
        return extractText(Net.post(url, body));
    }

    private static String extractText(String resp) throws Exception {
        JSONObject root = new JSONObject(resp);
        JSONArray cand = root.optJSONArray("candidates");
        if (cand == null || cand.length() == 0) {
            // maybe a prompt feedback block reason
            JSONObject pf = root.optJSONObject("promptFeedback");
            if (pf != null) throw new Exception("Blocked: " + pf.optString("blockReason", "unknown"));
            throw new Exception("Empty Gemini response");
        }
        JSONObject content = cand.getJSONObject(0).optJSONObject("content");
        StringBuilder sb = new StringBuilder();
        if (content != null) {
            JSONArray parts = content.optJSONArray("parts");
            if (parts != null) {
                for (int i = 0; i < parts.length(); i++) {
                    sb.append(parts.getJSONObject(i).optString("text", ""));
                }
            }
        }
        String t = sb.toString().trim();
        if (t.isEmpty()) {
            throw new Exception("No text returned (finishReason: "
                    + cand.getJSONObject(0).optString("finishReason", "?") + ")");
        }
        return t;
    }

    // ---- JSON helpers ----
    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    static String enc(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
