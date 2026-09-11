package com.arena.sentinel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dalvik (DEX) bytecode analyzer — pure Java (no Android deps).
 *
 * Walks the actual bytecode of every method and records:
 *  - real CALL SITES (which sensitive APIs are called, by which method, with what data)
 *  - a readable DECOMPILED BODY for each method that does something sensitive
 */
class DexFlow {

    static class CallSite {
        String callerClass;
        String callerMethod;
        String target;
        List<String> ctx = new ArrayList<>();
    }

    List<String> strings = new ArrayList<>();
    Set<String> definedClasses = new LinkedHashSet<>();
    Map<String, List<CallSite>> sensitive = new LinkedHashMap<>();
    Map<String, String> decompiled = new LinkedHashMap<>();   // callerClass.method -> smali-ish body
    Set<String> invoked = new LinkedHashSet<>();

    private byte[] dex;
    private ByteBuffer bb;
    private int stringIdsOff, stringIdsSize;
    private int typeIdsOff;
    private int fieldIdsOff;
    private int methodIdsOff;

    private static final String[][] SENS = {
            {"SMS usage", "smsmanager", "sendtextmessage", "sendmultiparttextmessage", "senddatamessage"},
            {"Device identifiers", "getdeviceid", "getsubscriberid", "getline1number", "getimei", "getsimserialnumber", "getmeid", "telephonymanager"},
            {"Contacts & SMS DB", "contactscontract", "content://sms", "calllog"},
            {"Location access", "getlatitude", "getlongitude", "getlastknownlocation", "locationmanager", "getaltitude", "requestlocationupdates"},
            {"Microphone / camera", "audiorecord", "mediarecorder", "/camera;->", "/camera2", "cameramanager;->open"},
            {"Dynamic code loading", "dexclassloader", "pathclassloader", "inmemorydexclassloader", "loaddex", "/dexpathlist"},
            {"Shell / execution", "runtime;->exec", "getruntime", "processbuilder", "/system/bin"},
            {"Reflection", "forname", "getdeclaredmethod", "getdeclaredfield", "setaccessible", "->invoke("},
            {"Cryptography", "secretkeyspec", "/cipher;->", "/mac;->", "messagedigest"},
            {"Overlay / system alert", "type_application_overlay", "windowmanager;->addview", "windowmanager$layoutparams"},
            {"Accessibility service", "accessibilityservice", "performglobalaction", "getrootinactivewindow"},
            {"Package install", "packageinstaller", "requestinstallpackage", "installpackage"},
            {"Network communication", "httpurlconnection", "urlconnection;->getoutputstream", "okhttp", "httppost", "httpclient", "multipart", "/request$builder", "url;->openconnection"},
            {"Clipboard", "clipboardmanager", "getprimaryclip"},
            {"Boot / persistence", "boot_completed"}
    };

    private static final int[] SIZE = new int[256];
    static {
        for (int i = 0; i < 256; i++) SIZE[i] = 1;
        int[] s2 = {0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1c,0x1f,0x20,0x22,0x23,
                0x29,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43,0x44,0x45,
                0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,
                0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,
                0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,
                0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,
                0x9b,0x9c,0x9d,0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
                0xa9,0xaa,0xab,0xac,0xcd,0xce,0xcf,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,
                0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf};
        for (int o : s2) SIZE[o] = 2;
        int[] s3 = {0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x6e,0x6f,0x70,
                0x71,0x72,0x74,0x75,0x76,0x77,0x78,0xfc,0xfd,0xfe,0xff};
        for (int o : s3) SIZE[o] = 3;
        SIZE[0x18] = 5;
    }

    void parse(byte[] data) {
        this.dex = data;
        if (dex == null || dex.length < 0x70) return;
        if (dex[0] != 0x64 || dex[1] != 0x65 || dex[2] != 0x78 || dex[3] != 0x0a) return;
        bb = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        stringIdsSize = bb.getInt(0x38);
        stringIdsOff = bb.getInt(0x3c);
        typeIdsOff = bb.getInt(0x44);
        fieldIdsOff = bb.getInt(0x54);
        methodIdsOff = bb.getInt(0x5c);
        int classDefsSize = bb.getInt(0x60);
        int classDefsOff = bb.getInt(0x64);

        for (int i = 0; i < Math.min(stringIdsSize, 40000); i++) {
            String s = readStringId(i);
            if (s != null && isAscii(s, 5, 200)) strings.add(s);
        }
        for (int i = 0; i < classDefsSize; i++) {
            int cd = classDefsOff + i * 32;
            if (cd + 32 > dex.length) break;
            int classIdx = bb.getInt(cd);
            int classDataOff = bb.getInt(cd + 24);
            String cls = readType(classIdx);
            if (cls != null) definedClasses.add(pretty(cls));
            if (classDataOff == 0) continue;
            readClassData(classDataOff, cls);
        }
    }

    void mergeFrom(DexFlow o) {
        if (o == null) return;
        for (String s : o.strings) if (strings.size() < 60000) strings.add(s);
        definedClasses.addAll(o.definedClasses);
        invoked.addAll(o.invoked);
        for (Map.Entry<String, List<CallSite>> e : o.sensitive.entrySet())
            sensitive.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).addAll(e.getValue());
        for (Map.Entry<String, String> e : o.decompiled.entrySet())
            decompiled.putIfAbsent(e.getKey(), e.getValue());
    }

    boolean hasCategory(String cat) {
        List<CallSite> l = sensitive.get(cat);
        return l != null && !l.isEmpty();
    }

    private void readClassData(int off, String cls) {
        int p = off;
        int sf = uleb(p); p = next(p);
        int ifs = uleb(p); p = next(p);
        int dm = uleb(p); p = next(p);
        int vm = uleb(p); p = next(p);
        for (int i = 0; i < sf + ifs; i++) { p = next(p); p = next(p); }
        for (int set = 0; set < 2; set++) {
            int count = set == 0 ? dm : vm;
            int methodIdx = 0;
            for (int i = 0; i < count; i++) {
                int idxDiff = uleb(p); p = next(p);
                p = next(p); // access flags
                int codeOff = uleb(p); p = next(p);
                methodIdx += idxDiff;
                String name = methodName(methodIdx);
                if (codeOff != 0) walkCode(codeOff, cls, name);
            }
        }
    }

    private void walkCode(int codeOff, String cls, String methodName) {
        if (codeOff + 16 > dex.length) return;
        int insnsSize = bb.getInt(codeOff + 12);
        int insnsStart = codeOff + 16;
        if (insnsSize <= 0 || insnsStart + insnsSize * 2 > dex.length) return;

        String[] recent = new String[6];
        int rc = 0;
        StringBuilder body = new StringBuilder();
        int lines = 0;
        boolean hit = false;
        int i = 0;
        while (i < insnsSize) {
            int pos = insnsStart + i * 2;
            int unit0 = bb.getChar(pos) & 0xffff;
            int opcode = unit0 & 0xff;
            String emitted = null;

            if (opcode == 0x1a) {
                int idx = bb.getChar(pos + 2) & 0xffff;
                String s = readStringId(idx);
                if (s != null) { recent[rc++ % recent.length] = s; emitted = "  const-string  \"" + clip(s, 60) + "\""; }
            } else if (opcode == 0x1b) {
                int idx = bb.getInt(pos + 2);
                String s = readStringId(idx);
                if (s != null) { recent[rc++ % recent.length] = s; emitted = "  const-string  \"" + clip(s, 60) + "\""; }
            } else if (opcode == 0x14) emitted = "  const  #" + bb.getInt(pos + 2);
            else if (opcode == 0x13) emitted = "  const/16  #" + (short) bb.getChar(pos + 2);
            else if (opcode == 0x12) { int v = (unit0 >> 12) & 0xf; if (v >= 8) v -= 16; emitted = "  const/4  #" + v; }
            else if (opcode == 0x15) emitted = "  const/high16  #" + bb.getChar(pos + 2);
            else if (opcode == 0x22) { String t = readType(bb.getChar(pos + 2) & 0xffff); if (t != null) emitted = "  new-instance  " + pretty(t); }
            else if (opcode == 0x1c) { String t = readType(bb.getChar(pos + 2) & 0xffff); if (t != null) emitted = "  const-class  " + pretty(t); }
            else if (opcode == 0x1f) { String t = readType(bb.getChar(pos + 2) & 0xffff); if (t != null) emitted = "  check-cast  " + pretty(t); }
            else if (opcode == 0x23) { String t = readType(bb.getChar(pos + 2) & 0xffff); if (t != null) emitted = "  new-array  " + pretty(t); }
            else if (opcode >= 0x0a && opcode <= 0x0c) emitted = "  move-result";
            else if (opcode == 0x0e) emitted = "  return-void";
            else if (opcode >= 0x0f && opcode <= 0x11) emitted = "  return";
            else if (opcode == 0x27) emitted = "  throw";
            else if (opcode >= 0x52 && opcode <= 0x6d) { String f = resolveField(bb.getChar(pos + 2) & 0xffff); if (f != null) emitted = "  field  " + f; }
            else if ((opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78) || opcode >= 0xfc) {
                int idx = bb.getChar(pos + 2) & 0xffff;
                String m = resolveMethod(idx);
                if (m != null) { invoked.add(m); emitted = "  invoke  " + m; if (sensitiveMatch(m)) { hit = true; addCallSite(cls, methodName, m, recent, rc); } }
            }

            if (emitted != null && lines < 48) { body.append(emitted).append('\n'); lines++; }
            i += SIZE[opcode];
            if (i <= 0) break;
        }
        if (hit && decompiled.size() < 8 && body.length() > 0) {
            decompiled.put(pretty(cls) + "." + (methodName == null ? "?" : methodName), body.toString());
        }
    }

    private boolean sensitiveMatch(String target) {
        String low = target.toLowerCase();
        for (String[] cat : SENS) {
            for (int k = 1; k < cat.length; k++) if (low.contains(cat[k])) return true;
        }
        return false;
    }

    private void addCallSite(String cls, String methodName, String target, String[] recent, int rc) {
        String low = target.toLowerCase();
        for (String[] cat : SENS) {
            boolean m = false;
            for (int k = 1; k < cat.length; k++) if (low.contains(cat[k])) { m = true; break; }
            if (!m) continue;
            List<CallSite> list = sensitive.computeIfAbsent(cat[0], c -> new ArrayList<>());
            if (list.size() >= 5) return;
            CallSite cs = new CallSite();
            cs.callerClass = pretty(cls);
            cs.callerMethod = methodName == null ? "?" : methodName;
            cs.target = pretty(target);
            int seen = 0;
            for (int j = 0; j < recent.length && seen < 3; j++) {
                String s = recent[(rc - 1 - j + recent.length * 4) % recent.length];
                if (s != null && looksLikeData(s)) { cs.ctx.add(clip(s, 80)); seen++; }
            }
            list.add(cs);
            return;
        }
    }

    // ---- low-level ----
    private String readStringId(int idx) {
        if (idx < 0 || idx >= stringIdsSize) return null;
        try {
            int off = bb.getInt(stringIdsOff + idx * 4);
            int p = off;
            while (p < dex.length && (dex[p++] & 0x80) != 0) { }
            int start = p;
            while (p < dex.length && dex[p] != 0) p++;
            return new String(dex, start, p - start, "UTF-8");
        } catch (Exception e) { return null; }
    }

    private String readType(int idx) {
        try { return readStringId(bb.getInt(typeIdsOff + idx * 4)); } catch (Exception e) { return null; }
    }

    private String resolveMethod(int idx) {
        try {
            int off = methodIdsOff + idx * 8;
            int classIdx = bb.getChar(off) & 0xffff;
            int nameIdx = bb.getInt(off + 4);
            String cls = readType(classIdx);
            String name = readStringId(nameIdx);
            if (cls == null || name == null) return null;
            return cls + "->" + name;
        } catch (Exception e) { return null; }
    }

    private String resolveField(int idx) {
        try {
            int off = fieldIdsOff + idx * 8;
            int classIdx = bb.getChar(off) & 0xffff;
            int typeIdx = bb.getChar(off + 2) & 0xffff;
            int nameIdx = bb.getInt(off + 4);
            String cls = readType(classIdx);
            String name = readStringId(nameIdx);
            if (cls == null || name == null) return null;
            return pretty(cls) + "." + name;
        } catch (Exception e) { return null; }
    }

    private String methodName(int idx) {
        try { return readStringId(bb.getInt(methodIdsOff + idx * 8 + 4)); } catch (Exception e) { return "?"; }
    }

    private int uleb(int off) {
        int result = 0, shift = 0, p = off;
        while (p < dex.length) { int x = dex[p++] & 0xff; result |= (x & 0x7f) << shift; if ((x & 0x80) == 0) break; shift += 7; }
        return result;
    }

    private int next(int off) { int p = off; while (p < dex.length) { int x = dex[p++] & 0xff; if ((x & 0x80) == 0) break; } return p; }

    private static boolean isAscii(String s, int min, int max) {
        if (s == null || s.length() < min || s.length() > max) return false;
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x20 || c >= 0x7f) return false; }
        return true;
    }

    private static boolean looksLikeData(String s) {
        if (s == null || s.length() < 3) return false;
        return s.contains("http") || s.contains("content://") || s.contains("://") || s.contains("/")
                || s.matches(".*[0-9]{4,}.*") || s.contains(".com") || s.contains(".net")
                || s.contains("password") || s.contains("key");
    }

    private static String pretty(String desc) {
        String s = desc.replace('/', '.');
        int sc = s.indexOf(';');
        if (s.startsWith("L") && sc > 0) s = s.substring(1, sc) + s.substring(sc + 1);
        return s.replace("->", ".").replace(";.", ".").replaceAll("\\.+", ".").trim();
    }

    private static String clip(String s, int max) { return s.length() <= max ? s : s.substring(0, max); }
}
