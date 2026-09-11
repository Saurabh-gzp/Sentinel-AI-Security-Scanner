package com.arena.sentinel;

import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Deep static analysis of an APK: manifest + real DEX bytecode call-flow + structure. */
class ApkAnalyzer {

    static class Result {
        String packageName = "";
        String label = "";
        String evidence = "";
        String payload = "";
        // structured fields for the agentic tools
        String version = "";
        List<String> permList = new ArrayList<>();
        int dangerPerms = 0;
        String exportedSummary = "";
        List<String> sensitiveSummary = new ArrayList<>();
        List<String> urls = new ArrayList<>();
        List<String> ips = new ArrayList<>();
        int dexCount = 0, soCount = 0;
        List<String> decompiledPreview = new ArrayList<>();
    }

    private static final int FLAGS =
            PackageManager.GET_PERMISSIONS | PackageManager.GET_ACTIVITIES |
                    PackageManager.GET_RECEIVERS | PackageManager.GET_SERVICES |
                    PackageManager.GET_PROVIDERS | PackageManager.GET_INTENT_FILTERS |
                    PackageManager.GET_META_DATA;

    private static final Pattern URL_RE =
            Pattern.compile("(https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{4,})");
    private static final Pattern IP_RE =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?\\b");

    private static final String[] DANGEROUS_PERMS = {
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "READ_PHONE_STATE",
            "PROCESS_OUTGOING_CALLS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALENDAR", "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO",
            "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
            "READ_PHONE_NUMBERS", "USE_SIP", "ADD_VOICEMAIL", "BODY_SENSORS",
            "GET_ACCOUNTS", "READ_CELL_BROADCASTS", "ANSWER_PHONE_CALLS"
    };

    // permission token -> DexFlow sensitive category it corresponds to
    private static final String[][] PERM_TO_CAT = {
            {"SEND_SMS", "SMS usage"}, {"RECEIVE_SMS", "SMS usage"}, {"READ_SMS", "SMS usage"}, {"RECEIVE_MMS", "SMS usage"},
            {"READ_PHONE_STATE", "Device identifiers"}, {"READ_PHONE_NUMBERS", "Device identifiers"},
            {"READ_CONTACTS", "Contacts & SMS DB"}, {"READ_CALL_LOG", "Contacts & SMS DB"}, {"GET_ACCOUNTS", "Contacts & SMS DB"},
            {"ACCESS_FINE_LOCATION", "Location access"}, {"ACCESS_COARSE_LOCATION", "Location access"}, {"ACCESS_BACKGROUND_LOCATION", "Location access"},
            {"RECORD_AUDIO", "Microphone / camera"}, {"CAMERA", "Microphone / camera"},
            {"SYSTEM_ALERT_WINDOW", "Overlay / system alert"}, {"REQUEST_INSTALL_PACKAGES", "Package install"}
    };

    static Result analyze(File apk, PackageManager pm) throws Exception {
        Result r = new Result();
        StringBuilder evidence = new StringBuilder();
        StringBuilder payload = new StringBuilder();

        // ---- structure (zip) ----
        int dexCount = 0, soCount = 0, total = 0;
        List<String> notable = new ArrayList<>();
        List<byte[]> dexes = new ArrayList<>();
        byte[] manifestBytes = null;
        try (ZipFile zf = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> e = zf.entries();
            while (e.hasMoreElements()) {
                ZipEntry ze = e.nextElement();
                if (ze.isDirectory()) continue;
                total++;
                String n = ze.getName();
                String low = n.toLowerCase();
                if (n.equals("AndroidManifest.xml")) manifestBytes = readEntry(zf, ze);
                if (n.startsWith("classes") && n.endsWith(".dex")) {
                    dexCount++;
                    if (dexes.size() < 8) dexes.add(readEntry(zf, ze));
                }
                if (n.endsWith(".so")) {
                    soCount++;
                    if (low.contains("frida") || low.contains("substrate") || low.contains("xposed"))
                        notable.add("Suspicious native lib: " + n);
                }
                if (low.contains("frida") || low.contains("xposed") || low.contains("substrate") || low.contains("gadget"))
                    notable.add("Hooking asset: " + n);
                if ((low.endsWith(".bin") || low.endsWith(".dat") || low.endsWith(".dex")) && n.startsWith("assets/") && ze.getSize() > 200_000)
                    notable.add("Large payload in assets: " + n + " (" + (ze.getSize() / 1024) + " KB)");
                if (low.endsWith(".apk") || low.endsWith(".jar")) notable.add("Bundled archive: " + n);
            }
        }

        // ---- manifest (package manager) ----
        PackageInfo pi = null;
        try { pi = pm.getPackageArchiveInfo(apk.getAbsolutePath(), FLAGS); } catch (Exception ignored) { }

        String pkg = "?", version = "?";
        int target = -1, minSdk = -1;
        boolean debuggable = false, allowBackup = true;
        List<String> permissions = new ArrayList<>();
        int expAct = 0, expSvc = 0, expRcv = 0, expPrv = 0;

        if (pi != null) {
            pkg = pi.packageName;
            long vc = android.os.Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : (long) pi.versionCode;
            version = (pi.versionName != null ? pi.versionName : "?") + " (" + vc + ")";
            if (pi.applicationInfo != null) {
                ApplicationInfo ai = pi.applicationInfo;
                target = ai.targetSdkVersion;
                minSdk = ai.minSdkVersion;
                debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                allowBackup = (ai.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
                r.label = ai.loadLabel(pm) != null ? ai.loadLabel(pm).toString() : pkg;
                if (pi.requestedPermissions != null) for (String p : pi.requestedPermissions) permissions.add(p);
                if (pi.activities != null) for (ActivityInfo a : pi.activities) if (a.exported) expAct++;
                if (pi.services != null) for (ServiceInfo s : pi.services) if (s.exported) expSvc++;
                if (pi.receivers != null) for (ActivityInfo a : pi.receivers) if (a.exported) expRcv++;
                if (pi.providers != null) for (ProviderInfo pr : pi.providers) if (pr.exported) expPrv++;
            }
        }
        r.packageName = pkg;

        int dangerPerms = 0;
        for (String p : permissions) for (String d : DANGEROUS_PERMS) if (p.contains(d)) dangerPerms++;

        // ---- REAL DEX bytecode analysis: call-flow ----
        DexFlow flow = new DexFlow();
        for (byte[] dex : dexes) {
            DexFlow f = new DexFlow();
            f.parse(dex);
            flow.mergeFrom(f);
            if (flow.strings.size() > 60000) break;
        }

        // ---- decode AndroidManifest.xml (like apktool) ----
        String manifestXml = "";
        if (manifestBytes != null) {
            try { manifestXml = new AxmlDecoder().decode(manifestBytes); } catch (Exception ignored) { }
        }

        // URLs / IPs from string pool
        Set<String> urls = new LinkedHashSet<>();
        Set<String> ips = new LinkedHashSet<>();
        for (String s : flow.strings) {
            if (urls.size() < 60 && (s.contains("http://") || s.contains("https://"))) {
                Matcher m = URL_RE.matcher(s);
                while (m.find() && urls.size() < 60) urls.add(m.group(1));
            }
            if (ips.size() < 30 && !s.startsWith("java.") && !s.contains("version")) {
                Matcher mip = IP_RE.matcher(s);
                if (mip.find()) ips.add(mip.group());
            }
        }

        // permission usage matrix
        List<String> permUsage = new ArrayList<>();
        for (String p : permissions) {
            String shortP = p.replace("android.permission.", "");
            String cat = null;
            for (String[] m : PERM_TO_CAT) if (p.contains(m[0])) { cat = m[1]; break; }
            if (cat == null) continue;
            boolean used = flow.hasCategory(cat);
            permUsage.add(shortP + " -> " + (used ? "USED (matching API calls found)" : "requested, NO matching call seen"));
        }

        // ---- evidence (display) ----
        evidence.append("PACKAGE: ").append(pkg).append('\n');
        if (!r.label.isEmpty()) evidence.append("LABEL: ").append(r.label).append('\n');
        evidence.append("VERSION: ").append(version).append('\n');
        evidence.append("SDK: target ").append(target < 0 ? "?" : target).append(" / min ").append(minSdk < 0 ? "?" : minSdk).append('\n');
        evidence.append("DEBUGGABLE: ").append(debuggable ? "YES" : "no").append("   ALLOW_BACKUP: ").append(allowBackup ? "yes" : "no").append('\n');
        evidence.append("\nPERMISSIONS (").append(permissions.size()).append(", ").append(dangerPerms).append(" dangerous):\n");
        for (String p : permissions) { String s = p.replace("android.permission.", ""); evidence.append("  ").append(s).append('\n'); }

        evidence.append("\nPERMISSION USAGE (requested vs actually used in code):\n");
        if (permUsage.isEmpty()) evidence.append("  (no sensitive permissions)\n");
        for (String u : permUsage) evidence.append("  ").append(u).append('\n');

        evidence.append("\nEXPORTED: activities ").append(expAct).append(", services ").append(expSvc)
                .append(", receivers ").append(expRcv).append(", providers ").append(expPrv).append('\n');
        evidence.append("STRUCTURE: ").append(dexCount).append(" dex, ").append(soCount).append(" native libs, ").append(total).append(" entries\n");
        if (!notable.isEmpty()) { evidence.append("NOTABLE FILES:\n"); for (String nf : notable) evidence.append("  ! ").append(nf).append('\n'); }

        if (!flow.definedClasses.isEmpty()) {
            evidence.append("\nAPP'S OWN CLASSES (").append(flow.definedClasses.size()).append("):\n");
            int c = 0;
            for (String cl : flow.definedClasses) { evidence.append("  ").append(cl).append('\n'); if (++c >= 24) break; }
        }

        evidence.append("\nCODE WORKFLOW — sensitive API call sites (real decompiled calls):\n");
        if (flow.sensitive.isEmpty()) evidence.append("  (no sensitive API calls found in bytecode)\n");
        for (Map.Entry<String, List<DexFlow.CallSite>> e : flow.sensitive.entrySet()) {
            evidence.append("  [").append(e.getKey()).append("]\n");
            int c = 0;
            for (DexFlow.CallSite cs : e.getValue()) {
                evidence.append("    ").append(cs.callerClass).append(".").append(cs.callerMethod)
                        .append("  ->  ").append(cs.target);
                if (!cs.ctx.isEmpty()) evidence.append("   |  ").append(String.join(" ; ", cs.ctx));
                evidence.append('\n');
                if (++c >= 4) break;
            }
        }

        // decompiled method bodies (real disassembly of sensitive methods)
        if (!flow.decompiled.isEmpty()) {
            evidence.append("\nDECOMPILED METHOD BODIES (sensitive methods — real bytecode disassembly):\n");
            int m = 0;
            for (Map.Entry<String, String> de : flow.decompiled.entrySet()) {
                evidence.append(".method ").append(de.getKey()).append('\n');
                evidence.append(Util.clip(de.getValue(), 1400));
                evidence.append(".end method\n\n");
                if (++m >= 6) break;
            }
        }

        // decoded manifest
        if (!manifestXml.isEmpty()) {
            evidence.append("\nDECODED AndroidManifest.xml (apktool-style):\n");
            evidence.append(Util.clip(manifestXml, 3200));
        }

        if (!ips.isEmpty()) {
            evidence.append("\nIP/PORT LITERALS (").append(ips.size()).append("):\n");
            int c = 0; for (String ip : ips) { evidence.append("  ").append(ip).append('\n'); if (++c >= 15) break; }
        }
        if (!urls.isEmpty()) {
            evidence.append("\nNETWORK URLS (").append(urls.size()).append("):\n");
            int c = 0; for (String u : urls) { evidence.append("  ").append(Util.clip(u, 110)).append('\n'); if (++c >= 25) break; }
        }

        // ---- payload (to AI) — emphasise behaviour, not permission lists ----
        payload.append("ANDROID APP — DECOMPILED BEHAVIOUR ANALYSIS (real data extracted from the APK)\n");
        payload.append("package: ").append(pkg).append("\n");
        payload.append("label: ").append(r.label.isEmpty() ? pkg : r.label).append("\n");
        payload.append("version: ").append(version).append("  targetSdk: ").append(target < 0 ? "?" : target)
                .append("  minSdk: ").append(minSdk < 0 ? "?" : minSdk).append("\n");
        payload.append("debuggable: ").append(debuggable).append("  allowBackup: ").append(allowBackup).append("\n");
        payload.append("permissions(").append(permissions.size()).append(", ").append(dangerPerms).append(" dangerous): ")
                .append(joinShort(permissions, 40)).append("\n");
        payload.append("exported: act=").append(expAct).append(" svc=").append(expSvc)
                .append(" rcv=").append(expRcv).append(" prv=").append(expPrv).append("\n");
        payload.append("dex=").append(dexCount).append(" nativeLibs=").append(soCount).append(" entries=").append(total).append("\n");
        if (!notable.isEmpty()) payload.append("notableFiles: ").append(String.join(" | ", Util.clip(notable, 3))).append("\n");

        payload.append("\nPERMISSION-vs-ACTUAL-USE (does the code really use each sensitive permission?):\n");
        if (permUsage.isEmpty()) payload.append("(none sensitive)\n");
        for (String u : permUsage) payload.append(u).append("\n");

        payload.append("\nDECOMPILED CODE WORKFLOW — which sensitive APIs are REALLY called, by which method, with what data:\n");
        if (flow.sensitive.isEmpty()) payload.append("(no sensitive API invocations in any class)\n");
        for (Map.Entry<String, List<DexFlow.CallSite>> e : flow.sensitive.entrySet()) {
            payload.append("[").append(e.getKey()).append("]\n");
            int c = 0;
            for (DexFlow.CallSite cs : e.getValue()) {
                payload.append("  ").append(cs.callerClass).append(".").append(cs.callerMethod)
                        .append(" -> ").append(cs.target);
                if (!cs.ctx.isEmpty()) payload.append("   data=").append(String.join(" ; ", cs.ctx));
                payload.append("\n");
                if (++c >= 4) break;
            }
        }

        if (!flow.definedClasses.isEmpty()) {
            payload.append("appOwnClasses(").append(Math.min(flow.definedClasses.size(), 15)).append("): ");
            int c = 0;
            for (String cl : flow.definedClasses) { payload.append(cl).append("  "); if (++c >= 15) break; }
            payload.append("\n");
        }
        if (!urls.isEmpty()) payload.append("networkUrls(").append(urls.size()).append("): ")
                .append(Util.clip(String.join("  ", urls), 1100)).append("\n");
        if (!ips.isEmpty()) payload.append("ipLiterals(").append(ips.size()).append("): ")
                .append(Util.clip(String.join("  ", ips), 300)).append("\n");

        if (!flow.decompiled.isEmpty()) {
            payload.append("\nDECOMPILED SENSITIVE METHODS (excerpt of real bytecode):\n");
            int m = 0;
            for (Map.Entry<String, String> de : flow.decompiled.entrySet()) {
                payload.append(".method ").append(de.getKey()).append("\n");
                payload.append(Util.clip(de.getValue(), 700)).append("\n");
                if (++m >= 3) break;
            }
        }
        if (!manifestXml.isEmpty())
            payload.append("\nmanifestExcerpt:\n").append(Util.clip(manifestXml, 1000)).append("\n");

        r.version = version;
        r.dangerPerms = dangerPerms;
        r.permList = permissions;
        r.exportedSummary = "act=" + expAct + " svc=" + expSvc + " rcv=" + expRcv + " prv=" + expPrv;
        r.dexCount = dexCount;
        r.soCount = soCount;
        for (String u : urls) r.urls.add(u);
        for (String ip : ips) r.ips.add(ip);
        for (Map.Entry<String, List<DexFlow.CallSite>> e : flow.sensitive.entrySet()) {
            DexFlow.CallSite cs = e.getValue().get(0);
            r.sensitiveSummary.add(e.getKey() + ": " + e.getValue().size() + " | "
                    + cs.callerClass + "." + cs.callerMethod + " -> " + cs.target);
        }
        int dp = 0;
        for (Map.Entry<String, String> e : flow.decompiled.entrySet()) {
            r.decompiledPreview.add(e.getKey() + "\n" + Util.clip(e.getValue(), 500));
            if (++dp >= 4) break;
        }

        r.evidence = evidence.toString();
        r.payload = payload.toString();
        return r;
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry ze) throws Exception {
        java.io.InputStream in = zf.getInputStream(ze);
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        in.close();
        return bo.toByteArray();
    }

    private static String joinShort(List<String> items, int max) {
        StringBuilder sb = new StringBuilder();
        int c = 0;
        for (String it : items) {
            if (c++ > 0) sb.append("; ");
            sb.append(it.replace("android.permission.", ""));
            if (c >= max) { sb.append(" …"); break; }
        }
        return sb.toString();
    }
}
