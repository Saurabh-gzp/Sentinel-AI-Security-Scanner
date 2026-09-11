package com.arena.sentinel;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Deterministic web rule engine -> EXACT verdict with concrete reasons (no "ho sakta hai").
 *  Ported & validated in Python before integration. Brand DB + scam templates + redirect/intent
 *  + malware-host + SSL rules. */
class WebEngine {

    static class Report {
        String verdict = "Safe";
        List<String> reasons = new ArrayList<>();
        String title = "";
        int forms = 0, pw = 0;
        List<String> actions = new ArrayList<>();
        List<String> scripts = new ArrayList<>();
        List<String> iframes = new ArrayList<>();
        String host = "";
        boolean sslOk = true;
    }

    // keyword + official domain(s)
    private static final String[][] BRANDS = {
            {"free fire", "garena.com", "freefiremobile.com", "freefireofficial.com"},
            {"freefire", "garena.com", "freefiremobile.com"},
            {"garena", "garena.com"},
            {"bgmi", "battlegroundsmobileindia.com", "krafton.com"},
            {"pubg", "pubg.com", "krafton.com"},
            {"paypal", "paypal.com"},
            {"google", "google.com", "accounts.google.com"},
            {"gmail", "accounts.google.com", "google.com"},
            {"facebook", "facebook.com"},
            {"instagram", "instagram.com"},
            {"whatsapp", "whatsapp.com", "web.whatsapp.com"},
            {"amazon", "amazon.com", "amazon.in"},
            {"flipkart", "flipkart.com"},
            {"netflix", "netflix.com"},
            {"microsoft", "microsoft.com", "login.microsoftonline.com", "live.com"},
            {"outlook", "outlook.com", "live.com", "login.microsoftonline.com"},
            {"office365", "login.microsoftonline.com", "office.com"},
            {"apple", "apple.com", "icloud.com"},
            {"icloud", "icloud.com", "apple.com"},
            {"sbi", "onlinesbi.com", "sbi.co.in"},
            {"hdfc", "hdfcbank.com"},
            {"icici", "icicibank.com"},
            {"axis", "axisbank.com"},
            {"phonepe", "phonepe.com"},
            {"paytm", "paytm.com"},
            {"binance", "binance.com"},
            {"telegram", "telegram.org"},
            {"spotify", "spotify.com"},
    };
    private static final String[] SCAM_KW = {
            "free fire", "freefire", "ff diamond", "diamond topup", "free diamond", "free uc",
            "bgmi uc", "redeem code", "free redeem", "free skin", "mod apk", "free topup",
            "coupon redeem", "diamond hack", "unlimited diamond", "free gift card", "free v bucks"
    };
    private static final String[] MAL_EXT = {
            ".exe", ".apk", ".jar", ".zip", ".dll", ".scr", ".bin", ".elf", ".msi", ".bat", "bin.sh"
    };
    private static final String[] SUSP_TLD = {
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "club", "work", "biz", "info", "rest",
            "date", "stream", "review", "country", "loan", "download", "kim", "sbs", "cyou", "monster"
    };
    // only these turn a brand mention into a phishing suspicion (brand name alone in path = legit tool/reference)
    private static final String[] LOGIN_KW = {
            "login", "signin", "sign-in", "log-in", "password", "credential", "wallet", "reset",
            "otp", "unlock", "recover", "banking", "webscr", "authwall", "verification"
    };
    private static final Pattern TITLE = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern OG = Pattern.compile("property=[\"']og:site_name[\"'][^>]*content=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ACTION = Pattern.compile("action=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCRIPT = Pattern.compile("<script[^>]+src=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IFRAME = Pattern.compile("<iframe[^>]+src=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);

    static Report analyze(WebProbe.Result p) {
        Report r = new Report();
        String h = p.html == null ? "" : p.html;
        r.host = p.host == null ? "" : p.host;
        r.sslOk = p.sslOk;

        Matcher tm = TITLE.matcher(h);
        r.title = tm.find() ? tm.group(1).replaceAll("\\s+", " ").trim() : "";
        Matcher om = OG.matcher(h);
        String og = om.find() ? om.group(1) : "";
        String urlpath = pathOf(p.askedUrl) + " " + pathOf(p.finalUrl);
        String low = h.toLowerCase();
        r.forms = count(low, "<form");
        r.pw = count(low, "type=\"password\"") + count(low, "type='password'");
        collect(ACTION, h, r.actions, 6);
        collect(SCRIPT, h, r.scripts, 8);
        collect(IFRAME, h, r.iframes, 4);

        String pathBlob = norm(urlpath + " " + r.title);
        String titleBlob = norm(r.title + " " + og);

        // 1) scam template
        for (String kw : SCAM_KW) {
            if (pathBlob.contains(norm(kw))) {
                r.reasons.add("SCAM TEMPLATE: '" + kw + "' (free diamond / topup / UC / redeem) pattern URL me hai -> official domain nahi, yeh lagbhag hamesha scam hota hai");
                r.verdict = "Malicious";
                break;
            }
        }
        // 2) brand login fraud (title + password form + non-official)
        if (!r.verdict.equals("Malicious") && r.pw > 0) {
            for (String[] b : BRANDS) {
                if (titleBlob.contains(norm(b[0])) && !official(r.host, b)) {
                    r.reasons.add("BRAND FRAUD: title me '" + b[0] + "' + login form, par domain '" + r.host + "' official '" + b[1] + "' nahi hai");
                    r.verdict = "Malicious";
                    break;
                }
            }
        }
        // 3) brand in path + LOGIN context + non-official (a brand name alone in path = legit tool — do NOT flag)
        if (!r.verdict.equals("Malicious") && loginKeyword(urlpath + " " + r.title)) {
            for (String[] b : BRANDS) {
                if (norm(urlpath).contains(norm(b[0])) && !official(r.host, b)) {
                    if (r.pw > 0) { r.reasons.add("BRAND FRAUD: path me '" + b[0] + "' + login form, domain non-official"); r.verdict = "Malicious"; }
                    else { r.reasons.add("brand '" + b[0] + "' + login keyword path/title me, par domain non-official (suspicious)"); r.verdict = "Suspicious"; }
                    break;
                }
            }
        }
        // 4) intent / package redirect (mobile phishing evasion)
        if (!r.verdict.equals("Malicious") && p.hasIntent) {
            r.reasons.add("MOBILE PHISHING: intent:// ... package=com.android.chrome redirect use karta hai (warning bypass karne ke liye)");
            r.verdict = "Malicious";
        }
        // 5) malware host (IP:port + executable)
        if (!r.verdict.equals("Malicious")) {
            String all = (p.askedUrl + " " + p.finalUrl + " " + join(p.hopUrls)).toLowerCase();
            if (r.host.matches("^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$") && anyContains(all, MAL_EXT)) {
                r.reasons.add("MALWARE HOST: IP:port (" + r.host + ") par executable download -> malware distribution");
                r.verdict = "Malicious";
            }
        }
        // 6) non-http scheme redirect (non-intent)
        if (!r.verdict.equals("Malicious") && p.hasNonHttp && !p.hasIntent) {
            r.reasons.add("suspicious redirect to non-http scheme");
            if (r.verdict.equals("Safe")) r.verdict = "Suspicious";
        }
        // 7) SSL problems
        if (!p.sslOk) {
            r.reasons.add("INVALID SSL: " + Util.clip(p.sslinfo, 120));
            if (r.verdict.equals("Safe")) r.verdict = "Suspicious";
        }
        // 8) suspicious TLD + brand name in title
        String tld = r.host.contains(".") ? r.host.substring(r.host.lastIndexOf('.') + 1) : "";
        if (!r.verdict.equals("Malicious") && r.host.length() > 0 && anyEquals(tld, SUSP_TLD) && brandIn(titleBlob)) {
            r.reasons.add("suspicious TLD '." + tld + "' + brand name in title");
            r.verdict = "Suspicious";
        }
        // safe
        if (r.verdict.equals("Safe") && r.reasons.isEmpty()) {
            if (knownGood(r.host)) r.reasons.add("known legitimate domain, clean behaviour");
            else if (p.sslOk && r.pw == 0 && !p.hasNonHttp) r.reasons.add("HTTPS valid, koi credential form ya suspicious redirect nahi mila");
        }
        return r;
    }

    private static String pathOf(String u) {
        try { return new URL(u).getPath(); } catch (Exception e) { return ""; }
    }
    private static String norm(String s) { return (s == null ? "" : s).toLowerCase().replaceAll("[\\s\\-_]+", ""); }
    private static boolean official(String host, String[] b) {
        if (host == null || host.isEmpty()) return false;
        for (int i = 1; i < b.length; i++) {
            String d = b[i];
            if (host.equals(d) || host.endsWith("." + d)) return true;
        }
        return false;
    }
    private static boolean loginKeyword(String s) {
        String n = norm(s);
        for (String kw : LOGIN_KW) if (n.contains(norm(kw))) return true;
        return false;
    }
    private static boolean brandIn(String titleBlob) {
        for (String[] b : BRANDS) if (titleBlob.contains(norm(b[0]))) return true;
        return false;
    }
    private static boolean knownGood(String host) {
        String[] kg = {"google.com", "github.com", "wikipedia.org", "mozilla.org", "cloudflare.com",
                "stackoverflow.com", "reddit.com", "apple.com", "microsoft.com", "amazon.in", "amazon.com",
                "garena.com", "freefiremobile.com", "instagram.com", "whatsapp.com", "yahoo.com"};
        for (String d : kg) if (host.equals(d) || host.endsWith("." + d)) return true;
        return false;
    }
    private static int count(String s, String sub) {
        int c = 0, i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) { c++; i += sub.length(); }
        return c;
    }
    private static void collect(Pattern p, String s, List<String> out, int max) {
        Matcher m = p.matcher(s);
        while (m.find()) { out.add(m.group(1)); if (out.size() >= max) break; }
    }
    private static boolean anyContains(String hay, String[] needles) { for (String n : needles) if (hay.contains(n)) return true; return false; }
    private static boolean anyEquals(String v, String[] opts) { for (String o : opts) if (o.equalsIgnoreCase(v)) return true; return false; }
    private static String join(List<String> l) { return l == null ? "" : String.join(" ", l); }
}
