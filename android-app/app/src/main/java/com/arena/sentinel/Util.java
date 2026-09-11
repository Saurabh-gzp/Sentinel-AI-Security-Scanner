package com.arena.sentinel;

import android.app.Activity;
import android.content.Context;
import android.content.res.Configuration;
import android.widget.Toast;
import java.util.regex.Pattern;

class Util {
    static void toast(Context c, String msg) {
        Toast.makeText(c, msg, Toast.LENGTH_LONG).show();
    }

    static void toast(Context c, int resId) {
        Toast.makeText(c, c.getString(resId), Toast.LENGTH_LONG).show();
    }

    static void ui(Activity a, Runnable r) {
        a.runOnUiThread(r);
    }

    static boolean isDarkMode(Context c) {
        int m = c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return m == Configuration.UI_MODE_NIGHT_YES;
    }

    /** Reliable internet check: validated capability OR a real probe to a captive-portal endpoint.
     *  Performs a network call — call from a BACKGROUND thread only. */
    static boolean online(Context c) {
        try {
            Object s = c.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (s instanceof android.net.ConnectivityManager) {
                android.net.ConnectivityManager cm = (android.net.ConnectivityManager) s;
                android.net.Network net = cm.getActiveNetwork();
                if (net == null) return false;
                android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                if (nc != null
                        && nc.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                        && nc.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    return true;
                }
            }
        } catch (Exception ignored) { }
        return reachProbe();
    }

    private static boolean reachProbe() {
        String[] urls = {
                "https://www.google.com/generate_204",
                "https://connectivitycheck.gstatic.com/generate_204",
                "https://www.gstatic.com/generate_204"
        };
        for (String u : urls) {
            try {
                java.net.HttpURLConnection con = (java.net.HttpURLConnection) new java.net.URL(u).openConnection();
                con.setConnectTimeout(1500);
                con.setReadTimeout(1500);
                con.setInstanceFollowRedirects(false);
                con.setRequestMethod("GET");
                int code = con.getResponseCode();
                con.disconnect();
                if (code > 0) return true;
            } catch (Exception e) { /* try next */ }
        }
        return false;
    }

    static String modeLabel(Context c) {
        return isDarkMode(c) ? "AUTO · DARK" : "AUTO · LIGHT";
    }

    /** Strip ```json fences and trim. */
    static String cleanJson(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.startsWith("```")) {
            int nl = t.indexOf('\n');
            if (nl > 0) t = t.substring(nl + 1);
            int f = t.lastIndexOf("```");
            if (f >= 0) t = t.substring(0, f);
            t = t.trim();
        }
        return t;
    }

    static String clip(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }

    // ---- abusive-language guard: never let rude/crude words reach the user ----
    private static final String[] BAD = {
            "chutiya", "chutiye", "chutiyapa", "chutia", "chutiyon", "chutiyo",
            "bhosdike", "bhosdiki", "bhosdi", "bhosdik", "bsdke",
            "madarchod", "maderchod", "mdrchod", "maderchoot",
            "bhenchod", "bhnchod", "bahenchod",
            "bsdk", "bkl",
            "lawde", "lavde", "laude", "lawda", "lodu", "lode",
            "gaandu", "gandu", "gaand", "gandfat",
            "harami", "haraami", "kaminey", "kamine", "kamini",
            "randi", "raand", "kutta", "kutti",
            "stupid", "idiot", "bewakoof", "chutmarika"
    };

    /** Remove any abusive/crude words so the report is always respectful. */
    static String sanitize(String s) {
        if (s == null || s.isEmpty()) return s;
        String out = s;
        for (String b : BAD) {
            out = out.replaceAll("(?i)\\b" + Pattern.quote(b) + "\\w*", "");
        }
        out = out.replaceAll("(?i)\\babe\\b", "").replaceAll("\\s{2,}", " ");
        out = out.replaceAll("\\s+([,!.])", "$1");
        return out.replaceAll("^[\\s,!.:;?]+", "").replaceAll("[\\s,!.:;?]+$", "").trim();
    }

    static java.util.List<String> clip(java.util.List<String> items, int max) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (items == null) return out;
        for (int i = 0; i < items.size() && i < max; i++) out.add(items.get(i));
        return out;
    }
}
