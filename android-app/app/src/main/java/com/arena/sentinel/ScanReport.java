package com.arena.sentinel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

class ScanReport {

    static final int SAFE = 0, SUSPICIOUS = 1, MALICIOUS = 2;

    int verdict = SUSPICIOUS;
    int confidence = 0;
    String summary = "";
    List<Risk> risks = new ArrayList<>();
    List<String> positives = new ArrayList<>();
    String recommendation = "";
    String practicalAdvice = "";
    String evidence = "";
    String target = "";
    String type = "Scan";

    static class Risk {
        String title, severity, detail;
        Risk(String t, String s, String d) { title = t; severity = s; detail = d; }
    }

    // ---------- prompt templates ----------
    static String appPrompt(String payload) {
        return "You are a senior mobile-malware reverse-engineer. You are given data extracted by DECOMPILING "
                + "an Android APK: the manifest, permissions, the app's own classes, AND — most important — the real "
                + "DECOMPILED CODE WORKFLOW showing exactly which sensitive APIs the code CALLS, from which method, and "
                + "the data near each call (URLs, file paths, keys).\n\n"
                + "STRICT RULES (follow exactly):\n"
                + "1. A PERMISSION LISTED ALONE IS NEVER EVIDENCE OF MALICE. Many benign apps legitimately request SMS, "
                + "location, contacts, camera, microphone, storage, phone-state, etc. for their stated purpose.\n"
                + "2. A risk counts ONLY if you can point to real CODE EVIDENCE: a specific sensitive API actually being "
                + "called, ideally with data flowing to an external/untrusted destination, or a clearly abusive pattern "
                + "(e.g. a 'flashlight'/'wallpaper'/game app that secretly sends premium SMS, reads IMEI and POSTs it to "
                + "an unknown server, loads remote DEX, runs shell as root, sets an overlay, or hides its real purpose).\n"
                + "3. Judge permission use vs APP PURPOSE. Infer the app's purpose from its package name, label and own "
                + "classes. An SMS/messaging app using SMS APIs = normal. A calculator/game using SMS+IMEI+network = red flag. "
                + "If 'requested, NO matching call seen' appears, that is at most a minor note, NOT a risk by itself.\n"
                + "4. Generic libraries (Google Play Services, ad SDKs, Firebase, Crashlytics, analytics) doing routine "
                + "telemetry are low severity, not malware.\n"
                + "5. If the workflow is clean and matches the app's stated purpose, verdict MUST be 'Safe' even if many "
                + "permissions exist. Do NOT pad with vague risks. An empty risks list is correct and acceptable.\n"
                + "LANGUAGE (very important): Write EVERY human-readable string (summary, risk titles, risk details, "
                + "positives, recommendation) in HINGLISH — that is Hindi written in Roman/English letters, exactly like "
                + "'ye app bilkul safe hai, isme koi backdoor ya data chori nahi hoti'. Do NOT use Devanagari Hindi "
                + "characters. Do NOT write plain English. Keep the JSON keys and the values of 'verdict' "
                + "(Safe/Suspicious/Malicious) and 'severity' (High/Medium/Low) exactly in English.\n"
                + "TONE (critical): Always be POLITE, RESPECTFUL and PROFESSIONAL, like a friendly security expert helping a user. NEVER use any abusive, insulting, crude, slang or condescending word toward the user (no 'chutiya','abe','stupid','idiot','bewakoof', etc.). Treat the user with respect.\n\n"
                + "Respond with ONLY valid JSON in EXACTLY this shape:\n"
                + "{\n"
                + "  \"verdict\": \"Safe\" | \"Suspicious\" | \"Malicious\",\n"
                + "  \"confidence\": <integer 0-100>,\n"
                + "  \"summary\": \"plain-language explanation; state the inferred app purpose and whether the sensitive "
                + "calls match it; cite the concrete calls/data you relied on\",\n"
                + "  \"risks\": [{\"title\": \"short\", \"severity\": \"High|Medium|Low\", \"detail\": \"cite the specific "
                + "API call + data destination from the workflow\"}],\n"
                + "  \"positives\": [\"concrete good signs, e.g. clean workflow matching purpose\"],\n"
                + "  \"recommendation\": \"actionable next step\",\n"
                + "  \"practical_advice\": \"real-world risks of USING this app beyond malware, in Hinglish — e.g. modded/hacked/cracked apps risk account ban + no updates + bundled malware; apps reading IMEI/contacts/location/messages risk privacy; signing in to unknown third-party apps risks account theft\"\n"
                + "}\n\n"
                + "DECOMPILED ANALYSIS:\n" + payload;
    }

    static String webPrompt(String payload) {
        return "A deterministic rule engine has ALREADY classified this website with a DEFINITIVE verdict from "
                + "concrete evidence (redirect chain, brand database, scam templates, SSL, credential forms, malware "
                + "patterns). Write the final report that STATES this verdict as a FACT — NO hedging; NEVER write "
                + "'ho sakta hai' / 'maybe' / 'could be'. Explain WHY in HINGLISH (Hindi in Roman/English letters, "
                + "no Devanagari, no plain English). If a screenshot image is attached, also use VISION to describe "
                + "what the page LOOKS like (fake login / copied brand). Keep 'verdict' and 'severity' values in "
                + "English exactly.\n"
                + "TONE (critical): Always be POLITE, RESPECTFUL and PROFESSIONAL, like a friendly security expert helping a user. NEVER use any abusive, insulting, crude, slang or condescending word toward the user (no 'chutiya','abe','stupid','idiot','bewakoof', etc.). Treat the user with respect.\n"
                + "ALSO include 'practical_advice': real-world risks of USING this site beyond malware, in Hinglish — "
                + "e.g. a third-party tool that takes your Instagram/TikTok/social handle can VIOLATE that platform's "
                + "terms and risk account suspension/ban; a page asking for login risks credential theft; a "
                + "free-reward/topup/diamond site is almost certainly a scam. Even a Safe verdict can carry such caveats.\n\n"
                + "Respond with ONLY JSON: {\"verdict\":...,\"confidence\":<int>,\"summary\":...,"
                + "\"risks\":[{\"title\":...,\"severity\":...,\"detail\":...}],\"positives\":[...],"
                + "\"recommendation\":...,\"practical_advice\":...}\n\n"
                + "ANALYSIS:\n" + payload;
    }

    // ---------- parse (tolerant) ----------
    static ScanReport parse(String json) {
        ScanReport r = new ScanReport();
        String clean = Util.cleanJson(json);
        try {
            JSONObject o = new JSONObject(clean);
            r.verdict = normVerdict(o.optString("verdict", "Suspicious"));
            r.confidence = readConfidence(o.opt("confidence"));
            r.summary = Util.sanitize(o.optString("summary", ""));
            JSONArray risks = o.optJSONArray("risks");
            if (risks != null) {
                for (int i = 0; i < risks.length() && i < 12; i++) {
                    Object item = risks.opt(i);
                    if (item instanceof JSONObject) {
                        JSONObject ro = (JSONObject) item;
                        r.risks.add(new Risk(
                                Util.sanitize(ro.optString("title", "Risk")),
                                normSev(ro.optString("severity", "Medium")),
                                Util.sanitize(ro.optString("detail", ""))));
                    } else if (item instanceof String) {
                        r.risks.add(new Risk("Risk", "Medium", item.toString()));
                    }
                }
            }
            JSONArray pos = o.optJSONArray("positives");
            if (pos != null) {
                for (int i = 0; i < pos.length() && i < 12; i++) {
                    Object item = pos.opt(i);
                    if (item != null && !item.toString().trim().isEmpty()) r.positives.add(Util.sanitize(item.toString().trim()));
                }
            }
            r.recommendation = Util.sanitize(o.optString("recommendation", ""));
            r.practicalAdvice = Util.sanitize(o.optString("practical_advice", o.optString("practicalAdvice", "")));
            if (r.summary.trim().isEmpty()) r.summary = o.optString("error", "");
            return r;
        } catch (Exception e) {
            // fallback: show raw model text as summary
            r.summary = Util.sanitize(Util.clip(json, 1800));
            r.recommendation = "AI did not return structured JSON. Review the evidence below.";
            r.confidence = 50;
            return r;
        }
    }

    private static int normVerdict(String v) {
        String l = v.toLowerCase();
        if (l.contains("malic")) return MALICIOUS;
        if (l.contains("susp")) return SUSPICIOUS;
        if (l.contains("safe") || l.contains("clean") || l.contains("benign")) return SAFE;
        return SUSPICIOUS;
    }

    private static String normSev(String s) {
        String l = s.toLowerCase();
        if (l.startsWith("high") || l.contains("crit")) return "High";
        if (l.startsWith("low")) return "Low";
        return "Medium";
    }

    private static int clamp(int v) { return v < 0 ? 0 : (v > 100 ? 100 : v); }

    private static int readConfidence(Object c) {
        if (c == null) return 50;
        if (c instanceof Number) return clamp(((Number) c).intValue());
        String s = c.toString().trim();
        if (s.matches("\\d+")) return clamp(Integer.parseInt(s));
        String l = s.toLowerCase();
        if (l.startsWith("high") || l.contains("very")) return 85;
        if (l.startsWith("med")) return 60;
        if (l.startsWith("low")) return 35;
        return 50;
    }
}
