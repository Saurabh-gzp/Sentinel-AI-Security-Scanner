package com.arena.sentinel;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Opens any Android package file: .apk, .apks (bundle), or .xapk (apk+OBB).
 *  Extracts the code-bearing base APK (+ notes splits), lists OBB files (NOT binary-scanned),
 *  and lets the agent decide what to scan. */
class PackageOpener {

    static class ApkEntry {
        String name; File file; long sizeKb; boolean base;
    }
    static class ObbEntry {
        String name; long sizeMb;
    }
    static class Opened {
        String type = "apk";                 // apk | apks | xapk | zip
        String sourceName = "";
        List<ApkEntry> apks = new ArrayList<>();
        List<ObbEntry> obb = new ArrayList<>();
        File baseApk = null;
        String error = "";
    }

    static Opened open(File src, File workDir) {
        Opened o = new Opened();
        o.sourceName = src.getName();
        workDir.mkdirs();
        String low = src.getName().toLowerCase();
        try {
            ZipFile zf = new ZipFile(src);
            boolean isPlainApk = zf.getEntry("AndroidManifest.xml") != null
                    && zf.getEntry("classes.dex") != null;
            if (isPlainApk) {
                o.type = "apk";
                ApkEntry e = new ApkEntry();
                e.name = src.getName();
                e.file = src;
                e.sizeKb = src.length() / 1024;
                e.base = true;
                o.apks.add(e);
                o.baseApk = src;
                zf.close();
                return o;
            }
            // container (apks / xapk / zip-of-apks)
            o.type = low.endsWith(".xapk") ? "xapk" : (low.endsWith(".apks") ? "apks" : "zip");
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                if (ze.isDirectory()) continue;
                String n = ze.getName();
                if (n.toLowerCase().endsWith(".apk")) {
                    File out = new File(workDir, safeName(n));
                    copyEntry(zf, ze, out);
                    ApkEntry e = new ApkEntry();
                    e.name = basename(n);
                    e.file = out;
                    e.sizeKb = ze.getSize() > 0 ? ze.getSize() / 1024 : out.length() / 1024;
                    o.apks.add(e);
                } else if (n.toLowerCase().endsWith(".obb")) {
                    ObbEntry b = new ObbEntry();
                    b.name = basename(n);
                    b.sizeMb = ze.getSize() > 0 ? ze.getSize() / (1024 * 1024) : 0;
                    o.obb.add(b);
                }
            }
            zf.close();
            // mark the base = the APK that actually contains code (classes.dex)
            for (ApkEntry e : o.apks) {
                if (hasCode(e.file)) { e.base = true; o.baseApk = e.file; break; }
            }
            if (o.baseApk == null && !o.apks.isEmpty()) {
                o.apks.get(0).base = true;
                o.baseApk = o.apks.get(0).file;
            }
            if (o.baseApk == null) o.error = "no APK found inside this package";
            return o;
        } catch (Exception e) {
            o.error = "open failed: " + e.getMessage();
            return o;
        }
    }

    private static boolean hasCode(File apk) {
        ZipFile zf = null;
        try {
            zf = new ZipFile(apk);
            return zf.getEntry("classes.dex") != null || zf.getEntry("AndroidManifest.xml") != null;
        } catch (Exception e) {
            return false;
        } finally {
            if (zf != null) try { zf.close(); } catch (Exception ignored) { }
        }
    }

    private static void copyEntry(ZipFile zf, ZipEntry ze, File out) throws Exception {
        InputStream in = zf.getInputStream(ze);
        FileOutputStream fo = new FileOutputStream(out);
        byte[] b = new byte[16384];
        int n;
        while ((n = in.read(b)) > 0) fo.write(b, 0, n);
        in.close();
        fo.close();
    }

    private static String safeName(String n) {
        String b = basename(n);
        return b.replaceAll("[^A-Za-z0-9._-]", "_");
    }
    private static String basename(String n) {
        int i = n.lastIndexOf('/');
        return i >= 0 ? n.substring(i + 1) : n;
    }
}
