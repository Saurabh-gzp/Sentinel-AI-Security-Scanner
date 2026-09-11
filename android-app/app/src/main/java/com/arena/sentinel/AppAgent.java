package com.arena.sentinel;

import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/** Agentic app scanner. Gemini uses tools (list_package, analyze_apk, finish_report) to decide
 *  how to open apk/apks/xapk and what to scan. Deterministic fallback if the loop fails.
 *  Must run on a background thread. */
class AppAgent {

    interface Progress { void update(String msg); }

    private static final String SYSTEM =
            "You are a mobile-malware reverse-engineer AGENT. You investigate Android packages "
                    + "(.apk, .apks app-bundle, or .xapk = apk+OBB) using tools, then give a final verdict via finish_report.\n"
                    + "RULES:\n"
                    + "- First call list_package to see the structure. apks/xapk hold several inner APKs; the BASE apk has the code, so analyze_apk on the base. Splits = only resources/native libs.\n"
                    + "- OBB files are huge media/asset expansion data — do NOT binary-scan them; just note their size.\n"
                    + "- analyze_apk returns REAL decompiled evidence: permissions, sensitive API call-sites (which method calls which API + data), URLs/IPs, and decompiled method bodies.\n"
                    + "- A permission ALONE is never malice. Judge by actual code behaviour vs the app's stated purpose. A messaging app using SMS = normal; a flashlight/game secretly sending SMS+IMEI to a server = malware.\n"
                    + "- Be DEFINITIVE (never 'ho sakta hai'/'maybe'). If clean, verdict MUST be Safe even with many permissions.\n"
                    + "- TONE (critical): Always POLITE, RESPECTFUL, PROFESSIONAL — like a friendly expert. NEVER use abusive/insulting/crude/slang words toward the user (no 'chutiya','abe','stupid','idiot','bewakoof', etc.). Treat the user with respect.\n"
                    + "- Write ALL human text in HINGLISH (Hindi in Roman/English letters, no Devanagari). Keep verdict and severity values in English.\n"
                    + "- Then call finish_report with: verdict, confidence(0-100), summary, risks[{title,severity,detail}], positives[], recommendation, practical_advice (real-world usage risks e.g. modded apps risk account-ban/no-updates/malware, IMEI/contacts apps risk privacy).";

    static ScanReport run(String key, String model, PackageOpener.Opened opened, PackageManager pm, Progress prog) {
        if (key == null || key.trim().isEmpty())
            throw new IllegalArgumentException("Gemini API key required. Open Settings and add your key before scanning.");
        ApkAnalyzer.Result baseAr = null;
        if (opened.baseApk != null) {
            if (prog != null) prog.update("Parsing manifest, DEX and native-library structure");
            try { baseAr = ApkAnalyzer.analyze(opened.baseApk, pm); } catch (Exception ignored) { }
        }
        ScanReport rep = null;
        try {
            rep = runAgentLoop(key, model, opened, pm, baseAr, prog);
        } catch (Exception ignored) { }
        if (rep == null) rep = fallbackReport(key, model, baseAr, prog);
        // finalize: attach deterministic proof + container header
        if (baseAr != null && (rep.evidence == null || rep.evidence.isEmpty())) rep.evidence = baseAr.evidence;
        rep.evidence = containerHeader(opened) + (rep.evidence == null ? "" : rep.evidence);
        if (rep.target == null || rep.target.isEmpty())
            rep.target = baseAr != null ? targetOf(baseAr) : opened.sourceName;
        rep.type = "App Scan";
        return rep;
    }

    private static ScanReport runAgentLoop(String key, String model, PackageOpener.Opened opened,
                                           PackageManager pm, ApkAnalyzer.Result baseAr, Progress prog) throws Exception {
        JSONArray contents = new JSONArray();
        contents.put(new JSONObject().put("role", "user").put("parts", new JSONArray()
                .put(new JSONObject().put("text", "Android package scan karo: " + opened.sourceName
                        + " (format: " + opened.type + "). Pehle list_package, phir analyze_apk (base par), "
                        + "phir finish_report. Khud decide karo kya scan karna hai."))));
        JSONArray tools = buildTools();
        Map<String, ApkAnalyzer.Result> cache = new HashMap<>();

        for (int turn = 0; turn < 6; turn++) {
            if (prog != null) prog.update("Agent investigating (step " + (turn + 1) + ")…");
            JSONObject resp = GeminiClient.toolCall(key, model, SYSTEM, contents, tools);
            JSONArray parts = GeminiClient.partsOf(resp);
            if (parts.length() == 0) return null;
            // finish_report?
            for (int i = 0; i < parts.length(); i++) {
                JSONObject fc = parts.optJSONObject(i) == null ? null : parts.optJSONObject(i).optJSONObject("functionCall");
                if (fc != null && "finish_report".equals(fc.optString("name"))) {
                    if (prog != null) prog.update("Preparing report…");
                    return ScanReport.parse(fc.optJSONObject("args") == null ? "{}" : fc.optJSONObject("args").toString());
                }
            }
            // echo model content, then run its tool calls
            JSONObject modelContent = resp.getJSONArray("candidates").getJSONObject(0).getJSONObject("content");
            contents.put(modelContent);
            JSONArray respParts = new JSONArray();
            boolean anyCall = false;
            for (int i = 0; i < parts.length(); i++) {
                JSONObject fc = parts.optJSONObject(i) == null ? null : parts.optJSONObject(i).optJSONObject("functionCall");
                if (fc == null) continue;
                anyCall = true;
                String name = fc.optString("name");
                JSONObject args = fc.optJSONObject("args");
                JSONObject result = execute(name, args, opened, pm, baseAr, cache, prog);
                respParts.put(new JSONObject().put("functionResponse",
                        new JSONObject().put("name", name).put("response", result)));
            }
            if (!anyCall) return null; // model gave text without tools/finish
            contents.put(new JSONObject().put("role", "user").put("parts", respParts));
        }
        return null; // turn limit
    }

    private static JSONObject execute(String name, JSONObject args, PackageOpener.Opened opened,
                                     PackageManager pm, ApkAnalyzer.Result baseAr,
                                     Map<String, ApkAnalyzer.Result> cache, Progress prog) {
        try {
            if ("list_package".equals(name)) return listPackageJson(opened);
            if ("analyze_apk".equals(name)) {
                String nm = (args == null) ? "base" : args.optString("name", "base");
                if (prog != null) prog.update("Decompiling + analyzing " + nm + "…");
                return analyzeApkJson(nm, opened, pm, baseAr, cache);
            }
            return new JSONObject().put("error", "unknown tool: " + name);
        } catch (Exception e) {
            try { return new JSONObject().put("error", e.getMessage() == null ? e.toString() : e.getMessage()); }
            catch (Exception e2) { return new JSONObject(); }
        }
    }

    private static JSONObject listPackageJson(PackageOpener.Opened o) throws Exception {
        JSONObject r = new JSONObject();
        r.put("format", o.type);
        r.put("fileName", o.sourceName);
        JSONArray apks = new JSONArray();
        for (PackageOpener.ApkEntry e : o.apks) {
            apks.put(new JSONObject().put("name", e.name).put("isBase", e.base).put("sizeKb", e.sizeKb));
        }
        r.put("innerApks", apks);
        JSONArray obb = new JSONArray();
        for (PackageOpener.ObbEntry b : o.obb) obb.put(new JSONObject().put("name", b.name).put("sizeMb", b.sizeMb));
        r.put("obbFiles", obb);
        r.put("baseApkName", baseName(o));
        r.put("note", o.type.equals("apk") ? "single APK file"
                : ("container with " + o.apks.size() + " APK(s). Base me code hota hai — analyze_apk base par chalao. "
                + (o.obb.isEmpty() ? "" : "OBB media/asset files hain (badi), unka sirf size note karo, binary-scan mat karo.")));
        return r;
    }

    private static JSONObject analyzeApkJson(String name, PackageOpener.Opened opened, PackageManager pm,
                                            ApkAnalyzer.Result baseAr, Map<String, ApkAnalyzer.Result> cache) throws Exception {
        ApkAnalyzer.Result ar;
        boolean wantBase = name.equalsIgnoreCase("base") || name.equals(baseName(opened))
                || (opened.baseApk != null && opened.baseApk.getName().startsWith(name));
        if (wantBase && baseAr != null) {
            ar = baseAr;
        } else {
            ar = cache.get(name);
            if (ar == null) {
                File f = findApk(name, opened);
                if (f == null) return new JSONObject().put("error", "apk '" + name + "' nahi mila. base use karo.");
                ar = ApkAnalyzer.analyze(f, pm);
                cache.put(name, ar);
            }
        }
        JSONObject o = new JSONObject();
        o.put("package", ar.packageName);
        o.put("label", ar.label);
        o.put("version", ar.version);
        o.put("permissionCount", ar.permList.size());
        o.put("dangerousPermissions", ar.dangerPerms);
        JSONArray perms = new JSONArray();
        int c = 0;
        for (String p : ar.permList) { perms.put(p.replace("android.permission.", "")); if (++c >= 25) break; }
        o.put("permissions", perms);
        o.put("exportedComponents", ar.exportedSummary);
        o.put("dexCount", ar.dexCount);
        o.put("nativeLibs", ar.soCount);
        JSONArray sens = new JSONArray();
        for (String s : ar.sensitiveSummary) sens.put(s);
        o.put("sensitiveApiCalls", sens);
        JSONArray urls = new JSONArray();
        c = 0;
        for (String u : ar.urls) { urls.put(u); if (++c >= 15) break; }
        o.put("urls", urls);
        JSONArray ips = new JSONArray();
        for (String ip : ar.ips) ips.put(ip);
        o.put("ipLiterals", ips);
        JSONArray dec = new JSONArray();
        for (String d : ar.decompiledPreview) dec.put(d);
        o.put("decompiledMethodBodies", dec);
        return o;
    }

    private static File findApk(String name, PackageOpener.Opened opened) {
        for (PackageOpener.ApkEntry e : opened.apks)
            if (e.name.equalsIgnoreCase(name) || e.file.getName().contains(name)) return e.file;
        return null;
    }

    private static String baseName(PackageOpener.Opened o) {
        for (PackageOpener.ApkEntry e : o.apks) if (e.base) return e.name;
        return o.apks.isEmpty() ? "" : o.apks.get(0).name;
    }

    private static JSONArray buildTools() throws Exception {
        JSONArray t = new JSONArray();
        t.put(new JSONObject().put("name", "list_package").put("description",
                "Opened package (apk/apks/xapk) ka structure return karta hai: inner APKs, base, OBB files.")
                .put("parameters", new JSONObject().put("type", "object").put("properties", new JSONObject())));
        t.put(new JSONObject().put("name", "analyze_apk").put("description",
                "Ek specific inner APK (default 'base') ka decompiled security analysis return karta hai.")
                .put("parameters", new JSONObject().put("type", "object")
                        .put("properties", new JSONObject().put("name", new JSONObject().put("type", "string")))));
        JSONObject fr = new JSONObject().put("name", "finish_report").put("description",
                "Final verdict report. Ye call karne ke baad scan complete ho jata hai.");
        JSONObject props = new JSONObject();
        props.put("verdict", new JSONObject().put("type", "string"));
        props.put("confidence", new JSONObject().put("type", "integer"));
        props.put("summary", new JSONObject().put("type", "string"));
        props.put("risks", new JSONObject().put("type", "array").put("items", new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                        .put("title", new JSONObject().put("type", "string"))
                        .put("severity", new JSONObject().put("type", "string"))
                        .put("detail", new JSONObject().put("type", "string")))));
        props.put("positives", new JSONObject().put("type", "array").put("items", new JSONObject().put("type", "string")));
        props.put("recommendation", new JSONObject().put("type", "string"));
        props.put("practical_advice", new JSONObject().put("type", "string"));
        fr.put("parameters", new JSONObject().put("type", "object").put("properties", props)
                .put("required", new JSONArray().put("verdict").put("summary")));
        t.put(fr);
        return t;
    }

    private static ScanReport fallbackReport(String key, String model, ApkAnalyzer.Result baseAr, Progress prog) {
        if (prog != null) prog.update("AI verdict (direct)…");
        ScanReport rep = new ScanReport();
        if (baseAr == null) {
            rep.verdict = ScanReport.SUSPICIOUS;
            rep.summary = "Package analyze nahi ho paaya.";
            return rep;
        }
        try {
            String resp = GeminiClient.generate(key, model, ScanReport.appPrompt(baseAr.payload));
            rep = ScanReport.parse(resp);
        } catch (Exception e) {
            rep.verdict = ScanReport.SUSPICIOUS;
            rep.summary = "AI error: " + e.getMessage();
        }
        rep.evidence = baseAr.evidence;
        return rep;
    }

    private static String containerHeader(PackageOpener.Opened o) {
        StringBuilder s = new StringBuilder();
        s.append("PACKAGE FORMAT: ").append(o.type).append("  (").append(o.sourceName).append(")\n");
        if (!o.type.equals("apk")) {
            s.append("Inner APKs: ");
            for (PackageOpener.ApkEntry e : o.apks) s.append(e.name).append(e.base ? " (base, code)" : " (split)").append(", ");
            s.append("\n");
            if (!o.obb.isEmpty()) {
                s.append("OBB files (large expansion data — not code, size noted only):\n");
                for (PackageOpener.ObbEntry b : o.obb) s.append("  ").append(b.name).append("  (~").append(b.sizeMb).append(" MB)\n");
            }
        }
        return s.append("\n").toString();
    }

    private static String targetOf(ApkAnalyzer.Result ar) {
        return (ar.label == null || ar.label.isEmpty()) ? ar.packageName : ar.label + "  ·  " + ar.packageName;
    }
}
