package com.arena.sentinel;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

/** Fetches a website, inspects SSL/redirects/HTML, and gathers phishing signals. */
class WebAnalyzer {

    static class Result {
        String host = "";
        String finalUrl = "";
        String evidence = "";
        String payload = "";
    }

    private static final Pattern TITLE = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern META_DESC = Pattern.compile(
            "<meta[^>]+(?:name|property)=[\"'](?:description|og:description)[\"'][^>]*content=[\"']([^\"']*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern OG_SITE = Pattern.compile(
            "<meta[^>]+property=[\"']og:site_name[\"'][^>]*content=[\"']([^\"']*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCRIPT_SRC = Pattern.compile("<script[^>]+src=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IFRAME_SRC = Pattern.compile("<iframe[^>]+src=[\"']([^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_HREF = Pattern.compile("href=[\"'](https?://[^\"']+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IP_HOST = Pattern.compile("^[\\d.]+(:\\d+)?$");

    private static final String[] SUSP_TLD = {
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "club", "work",
            "biz", "info", "ru", "cn", "rest", "date", "stream", "review", "country", "loan", "download", "kim"
    };
    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at"
    };
    private static final String[] BRAND_WORDS = {
            "login", "signin", "verify", "account", "secure", "update", "confirm", "wallet",
            "bank", "paypal", "recover", "unlock", "suspended", "support", "billing", "authentication"
    };

    private static class Response {
        int code;
        String finalUrl, contentType, server;
        long len;
        String body;
        boolean sslValid = true;
        String sslInfo = "";
        List<String> chain = new ArrayList<>();
    }

    static Result scan(String input) throws Exception {
        Result r = new Result();
        String base = input.trim();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        if (base.isEmpty()) throw new IllegalArgumentException("empty url");

        String withScheme = base.contains("://") ? base : "https://" + base;
        Response resp;
        String lastErr = "";
        try {
            resp = fetch(withScheme);
        } catch (Exception e) {
            lastErr = e.getMessage() == null ? e.toString() : e.getMessage();
            if (!base.contains("://")) {
                resp = fetch("http://" + base);
            } else {
                throw e;
            }
        }

        String host;
        try { host = new URL(resp.finalUrl).getHost().toLowerCase(); } catch (Exception e) { host = "?"; }
        r.host = host;
        r.finalUrl = resp.finalUrl;
        String html = resp.body == null ? "" : resp.body;
        String head = html.length() > 12000 ? html.substring(0, 12000) : html;

        // ---- HTML features ----
        String title = match(TITLE, head); if (title == null) title = "";
        title = title.replaceAll("\\s+", " ").trim();
        String desc = match(META_DESC, head); if (desc == null) desc = "";
        String siteName = match(OG_SITE, head); if (siteName == null) siteName = "";
        int forms = count(html, "<form");
        int pwFields = count(html.toLowerCase(), "type=\"password\"") + count(html.toLowerCase(), "type='password'");
        Set<String> extScripts = new LinkedHashSet<>();
        collect(SCRIPT_SRC, head, extScripts, host);
        Set<String> iframes = new LinkedHashSet<>();
        collect(IFRAME_SRC, head, iframes, host);
        int externalLinks = 0;
        Matcher mh = LINK_HREF.matcher(head);
        while (mh.find()) if (!sameHost(mh.group(1), host)) externalLinks++;

        int evalCalls = count(html, "eval(");
        int atobCalls = count(html, "atob(");
        int fromCharCode = count(html, "String.fromCharCode");
        int docWrite = count(html, "document.write");
        int unescape = count(html, "unescape(");
        boolean heavyHex = Pattern.compile("(?:%[0-9a-fA-F]{2}){15,}").matcher(html).find();
        int obf = evalCalls + atobCalls + fromCharCode + docWrite + unescape + (heavyHex ? 3 : 0);

        // ---- heuristics ----
        boolean usesHttps = resp.finalUrl.startsWith("https");
        boolean hostIsIp = IP_HOST.matcher(host).matches();
        boolean punycode = host.contains("xn--");
        int labels = host.isEmpty() ? 0 : host.split("\\.").length;
        boolean manySub = labels >= 5;
        String tld = labels >= 2 ? host.split("\\.")[host.split("\\.").length - 1] : "";
        boolean suspTld = false;
        for (String s : SUSP_TLD) if (s.equalsIgnoreCase(tld)) suspTld = true;
        boolean shortener = false;
        for (String s : SHORTENERS) if (host.endsWith(s)) shortener = true;
        boolean brandWordsInHost = false;
        for (String b : BRAND_WORDS) if (host.contains(b)) brandWordsInHost = true;
        boolean loginOnHttp = pwFields > 0 && !usesHttps;
        boolean crossRedirect = false;
        for (String h : resp.chain) if (!h.equalsIgnoreCase(host)) crossRedirect = true;

        int riskPoints = 0;
        if (!usesHttps) riskPoints += 2;
        if (!resp.sslValid) riskPoints += 4;
        if (hostIsIp) riskPoints += 3;
        if (punycode) riskPoints += 3;
        if (manySub) riskPoints += 1;
        if (suspTld) riskPoints += 2;
        if (shortener) riskPoints += 2;
        if (brandWordsInHost) riskPoints += 2;
        if (loginOnHttp) riskPoints += 4;
        if (crossRedirect) riskPoints += 1;
        if (pwFields > 0 && extScripts.size() > 0) riskPoints += 1;
        if (obf >= 4) riskPoints += 2;

        // ---- evidence ----
        StringBuilder ev = new StringBuilder();
        ev.append("URL: ").append(resp.finalUrl).append('\n');
        ev.append("HOST: ").append(host).append('\n');
        ev.append("HTTP STATUS: ").append(resp.code).append('\n');
        ev.append("CONTENT-TYPE: ").append(nullTo(resp.contentType, "?")).append('\n');
        ev.append("SERVER: ").append(nullTo(resp.server, "?")).append('\n');
        ev.append("SIZE: ").append(resp.len < 0 ? "?" : resp.len + " bytes").append('\n');
        ev.append("SSL/TLS: ").append(usesHttps ? (resp.sslValid ? "valid HTTPS" : "INVALID certificate") : "no HTTPS (cleartext)").append('\n');
        if (!resp.sslInfo.isEmpty()) ev.append("SSL DETAIL: ").append(resp.sslInfo).append('\n');
        ev.append("REDIRECT CHAIN: ").append(resp.chain.isEmpty() ? "direct" : String.join(" -> ", resp.chain)).append('\n');
        ev.append('\n').append("TITLE: ").append(title).append('\n');
        if (!siteName.isEmpty()) ev.append("SITE NAME: ").append(siteName).append('\n');
        if (!desc.isEmpty()) ev.append("DESCRIPTION: ").append(Util.clip(desc, 160)).append('\n');
        ev.append('\n').append("FORMS: ").append(forms)
                .append("   PASSWORD FIELDS: ").append(pwFields)
                .append("   EXTERNAL LINKS: ").append(externalLinks).append('\n');
        ev.append("EXTERNAL SCRIPTS (").append(extScripts.size()).append("):");
        if (extScripts.isEmpty()) ev.append(" none"); else ev.append('\n');
        int c = 0; for (String s : extScripts) { ev.append("  ").append(Util.clip(s, 110)).append('\n'); if (++c >= 12) break; }
        if (!iframes.isEmpty()) {
            ev.append("IFRAMES:\n");
            int i = 0; for (String s : iframes) { ev.append("  ").append(Util.clip(s, 110)).append('\n'); if (++i >= 8) break; }
        }
        ev.append('\n').append("HEURISTICS:\n");
        ev.append("  uses HTTPS        : ").append(yesno(usesHttps)).append('\n');
        ev.append("  valid certificate : ").append(usesHttps ? yesno(resp.sslValid) : "n/a").append('\n');
        ev.append("  host is IP literal: ").append(yesno(hostIsIp)).append('\n');
        ev.append("  punycode/IDN host : ").append(yesno(punycode)).append('\n');
        ev.append("  many subdomains   : ").append(yesno(manySub)).append('\n');
        ev.append("  suspicious TLD    : ").append(yesno(suspTld)).append('\n');
        ev.append("  URL shortener     : ").append(yesno(shortener)).append('\n');
        ev.append("  brand keywords    : ").append(yesno(brandWordsInHost)).append('\n');
        ev.append("  login over HTTP   : ").append(yesno(loginOnHttp)).append('\n');
        ev.append("  cross-domain redir: ").append(yesno(crossRedirect)).append('\n');
        ev.append("  obfuscation signs : ").append(obf >= 4 ? "yes (" + obf + ")" : "low").append('\n');
        ev.append('\n').append("HEURISTIC RISK SCORE: ").append(riskPoints).append(" / ~28");

        // ---- payload ----
        StringBuilder p = new StringBuilder();
        p.append("WEBSITE SCAN (real fetched data)\n");
        p.append("finalUrl: ").append(resp.finalUrl).append("\n");
        p.append("host: ").append(host).append(" tld: ").append(tld).append("\n");
        p.append("httpStatus: ").append(resp.code).append("  contentType: ").append(nullTo(resp.contentType, "?"))
                .append("  server: ").append(nullTo(resp.server, "?")).append("\n");
        p.append("ssl: ").append(usesHttps ? (resp.sslValid ? "valid HTTPS" : "INVALID CERT") : "NO HTTPS (cleartext)")
                .append("  sslDetail: ").append(resp.sslInfo).append("\n");
        p.append("redirectChain: ").append(resp.chain.isEmpty() ? "direct" : String.join(" -> ", resp.chain)).append("\n");
        p.append("title: ").append(title).append("\n");
        p.append("siteName: ").append(siteName).append("\n");
        p.append("description: ").append(Util.clip(desc, 200)).append("\n");
        p.append("forms: ").append(forms).append(" passwordFields: ").append(pwFields).append(" externalLinks: ").append(externalLinks).append("\n");
        if (!extScripts.isEmpty()) p.append("externalScripts: ").append(Util.clip(String.join("  ", extScripts), 700)).append("\n");
        if (!iframes.isEmpty()) p.append("iframes: ").append(Util.clip(String.join("  ", iframes), 400)).append("\n");
        p.append("heuristics: https=").append(usesHttps).append(" validCert=").append(usesHttps && resp.sslValid)
                .append(" hostIsIp=").append(hostIsIp).append(" punycode=").append(punycode)
                .append(" manySub=").append(manySub).append(" suspTld=").append(suspTld)
                .append(" shortener=").append(shortener).append(" brandWords=").append(brandWordsInHost)
                .append(" loginOnHttp=").append(loginOnHttp).append(" crossRedirect=").append(crossRedirect)
                .append(" obfuscation=").append(obf).append(" riskScore=").append(riskPoints).append("\n");

        r.evidence = ev.toString();
        r.payload = p.toString();
        return r;
    }

    private static Response fetch(String urlStr) throws Exception {
        Response res = new Response();
        URL url = new URL(urlStr);
        for (int hop = 0; hop < 6; hop++) {
            String h = url.getHost();
            if (!res.chain.isEmpty() && res.chain.get(res.chain.size() - 1).equalsIgnoreCase(h)) {
                // same host again, fine
            }
            if (res.chain.isEmpty() || !res.chain.get(res.chain.size() - 1).equalsIgnoreCase(h)) res.chain.add(h);
            HttpURLConnection c = (HttpURLConnection) url.openConnection();
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(18000);
            c.setReadTimeout(25000);
            c.setRequestMethod("GET");
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 SentinelScanner/1.0");
            c.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*");
            try {
                res.code = c.getResponseCode();
            } catch (javax.net.ssl.SSLException se) {
                res.sslValid = false;
                res.sslInfo = Util.clip(se.getMessage(), 160);
                // try to read error body anyway
                res.finalUrl = url.toString();
                res.contentType = c.getContentType();
                res.server = c.getHeaderField("Server");
                c.disconnect();
                return res;
            }
            res.contentType = c.getContentType();
            res.server = c.getHeaderField("Server");
            res.len = c.getContentLengthLong();
            if (c instanceof HttpsURLConnection) {
                try {
                    java.security.cert.Certificate[] certs = ((HttpsURLConnection) c).getServerCertificates();
                    if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                        X509Certificate x = (X509Certificate) certs[0];
                        res.sslInfo = "issuer=" + x.getIssuerX500Principal().getName()
                                + "; expires=" + x.getNotAfter();
                    }
                } catch (Exception ignore) { }
            }
            boolean redir = res.code == 301 || res.code == 302 || res.code == 303 || res.code == 307 || res.code == 308;
            if (redir) {
                String loc = c.getHeaderField("Location");
                c.disconnect();
                if (loc == null || loc.isEmpty()) break;
                url = new URL(url, loc);
                continue;
            }
            res.finalUrl = url.toString();
            InputStream in = (res.code >= 400) ? c.getErrorStream() : c.getInputStream();
            res.body = readUpTo(in, 320_000);
            c.disconnect();
            return res;
        }
        res.finalUrl = url.toString();
        return res;
    }

    private static String readUpTo(InputStream in, int max) throws Exception {
        if (in == null) return "";
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n, total = 0;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
            total += n;
            if (total >= max) break;
        }
        in.close();
        return new String(bo.toByteArray(), "UTF-8");
    }

    private static String match(Pattern p, String s) {
        Matcher m = p.matcher(s);
        return m.find() ? m.groupCount() >= 1 ? m.group(1) : m.group() : null;
    }

    private static int count(String s, String sub) {
        int c = 0, i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) { c++; i += sub.length(); }
        return c;
    }

    private static void collect(Pattern p, String s, Set<String> out, String host) {
        Matcher m = p.matcher(s);
        while (m.find()) {
            String v = m.group(1).trim();
            if (!v.isEmpty()) out.add(v);
            if (out.size() >= 40) break;
        }
    }

    private static boolean sameHost(String url, String host) {
        try { return new URL(url).getHost().equalsIgnoreCase(host); } catch (Exception e) { return false; }
    }

    private static String yesno(boolean b) { return b ? "YES" : "no"; }
    private static String nullTo(String s, String d) { return s == null ? d : s; }

    // ---- accept ANY link ----
    static String normalize(String raw) {
        if (raw == null) return "";
        String u = raw.trim().replaceAll("^[\\s\"'`<>\\[\\]()]+|[\\s\"'`<>\\[\\]()]+$", "");
        if (u.isEmpty()) return "";
        if (u.contains("://")) return u;
        return "https://" + u;
    }

    private static String hostOf(String u) {
        try { return new URL(u).getHost().toLowerCase(); } catch (Exception e) { return ""; }
    }

    /** Build {evidence, payload} from a real Chromium (WebView) render. */
    static String[] fromRender(WebRender.Result r) {
        String html = r.renderedHtml == null ? "" : r.renderedHtml;
        String head = html.length() > 12000 ? html.substring(0, 12000) : html;
        String host = hostOf(r.finalUrl);
        if (host.isEmpty()) host = hostOf(r.askedUrl);

        String title = nullTo(match(TITLE, head), "");
        title = title.replaceAll("\\s+", " ").trim();
        String desc = nullTo(match(META_DESC, head), "");
        String siteName = nullTo(match(OG_SITE, head), "");
        int forms = count(html, "<form");
        int pwFields = count(html.toLowerCase(), "type=\"password\"") + count(html.toLowerCase(), "type='password'");
        Set<String> extScripts = new LinkedHashSet<>();
        collect(SCRIPT_SRC, head, extScripts, host);
        Set<String> iframes = new LinkedHashSet<>();
        collect(IFRAME_SRC, head, iframes, host);
        int externalLinks = 0;
        Matcher mh = LINK_HREF.matcher(head);
        while (mh.find()) if (!sameHost(mh.group(1), host)) externalLinks++;

        int evalCalls = count(html, "eval("), atobCalls = count(html, "atob("),
                fromCharCode = count(html, "String.fromCharCode"), docWrite = count(html, "document.write"),
                unescape = count(html, "unescape(");
        boolean heavyHex = Pattern.compile("(?:%[0-9a-fA-F]{2}){15,}").matcher(html).find();
        int obf = evalCalls + atobCalls + fromCharCode + docWrite + unescape + (heavyHex ? 3 : 0);

        boolean usesHttps = r.finalUrl.startsWith("https") || r.askedUrl.startsWith("https");
        boolean sslValid = usesHttps && r.sslErrors.isEmpty();
        boolean hostIsIp = IP_HOST.matcher(host).matches();
        boolean punycode = host.contains("xn--");
        int labels = host.isEmpty() ? 0 : host.split("\\.").length;
        boolean manySub = labels >= 5;
        String tld = labels >= 2 ? host.split("\\.")[labels - 1] : "";
        boolean suspTld = false;
        for (String s : SUSP_TLD) if (s.equalsIgnoreCase(tld)) suspTld = true;
        boolean shortener = false;
        for (String s : SHORTENERS) if (host.endsWith(s)) shortener = true;
        boolean brandWordsInHost = false;
        for (String b : BRAND_WORDS) if (host.contains(b)) brandWordsInHost = true;
        boolean loginOnHttp = pwFields > 0 && !usesHttps;
        boolean crossRedirect = false;
        for (String h : r.redirectHosts) if (!h.equalsIgnoreCase(host)) crossRedirect = true;
        boolean sslProblem = !r.sslErrors.isEmpty();
        boolean httpErrors = !r.httpErrors.isEmpty();

        // external resources actually loaded by the browser
        Set<String> extRes = new LinkedHashSet<>();
        int totalReq = r.requests.size();
        for (String u : r.requests) {
            String h = hostOf(u);
            if (!h.isEmpty() && !h.equalsIgnoreCase(host)) extRes.add(u);
            if (extRes.size() >= 30) break;
        }

        int risk = 0;
        if (!usesHttps) risk += 2;
        if (sslProblem) risk += 4;
        if (hostIsIp) risk += 3;
        if (punycode) risk += 3;
        if (manySub) risk += 1;
        if (suspTld) risk += 2;
        if (shortener) risk += 2;
        if (brandWordsInHost) risk += 2;
        if (loginOnHttp) risk += 4;
        if (crossRedirect) risk += 1;
        if (httpErrors) risk += 1;
        if (obf >= 4) risk += 2;

        boolean hasShot = r.screenshot != null;

        StringBuilder ev = new StringBuilder();
        ev.append("URL: ").append(r.finalUrl.isEmpty() ? r.askedUrl : r.finalUrl).append('\n');
        ev.append("HOST: ").append(host).append("   TLD: ").append(tld).append('\n');
        ev.append("RENDERED IN: real Chromium/WebView (JS executed)\n");
        ev.append("TITLE: ").append(title).append('\n');
        if (!siteName.isEmpty()) ev.append("SITE NAME: ").append(siteName).append('\n');
        if (!desc.isEmpty()) ev.append("DESCRIPTION: ").append(Util.clip(desc, 160)).append('\n');
        ev.append('\n').append("SECURITY:\n");
        ev.append("  HTTPS         : ").append(yesno(usesHttps)).append('\n');
        ev.append("  SSL/TLS valid : ").append(usesHttps ? yesno(sslValid) : "n/a").append('\n');
        for (String e : r.sslErrors) ev.append("  SSL error     : ").append(e).append('\n');
        for (String e : r.httpErrors) ev.append("  HTTP/load err : ").append(Util.clip(e, 100)).append('\n');
        ev.append("  Redirect hosts: ").append(r.redirectHosts.isEmpty() ? "none" : String.join(", ", r.redirectHosts)).append('\n');
        ev.append('\n').append("PAGE CONTENT (rendered DOM):\n");
        ev.append("  Forms: ").append(forms).append("   Password fields: ").append(pwFields)
                .append("   External links: ").append(externalLinks).append("   Obfuscation: ").append(obf).append('\n');
        ev.append("  External scripts loaded (").append(extScripts.size()).append("):\n");
        int c = 0; for (String s : extScripts) { ev.append("    ").append(Util.clip(s, 110)).append('\n'); if (++c >= 12) break; }
        if (!iframes.isEmpty()) {
            ev.append("  Iframes:\n");
            int i = 0; for (String s : iframes) { ev.append("    ").append(Util.clip(s, 110)).append('\n'); if (++i >= 8) break; }
        }
        ev.append('\n').append("ALL RESOURCES LOADED BY BROWSER (").append(totalReq).append("), external hosts:\n");
        c = 0; for (String s : extRes) { ev.append("    ").append(Util.clip(s, 110)).append('\n'); if (++c >= 14) break; }
        if (!r.console.isEmpty()) {
            ev.append('\n').append("JS CONSOLE:\n");
            c = 0; for (String m : r.console) { ev.append("    ").append(Util.clip(m, 120)).append('\n'); if (++c >= 10) break; }
        }
        ev.append('\n').append("HEURISTIC RISK SCORE: ").append(risk);
        ev.append("\nVision screenshot captured for AI: ").append(hasShot ? "YES" : "no (page blank/unavailable)");
        if (!r.error.isEmpty()) ev.append("\nNOTE: ").append(r.error);

        StringBuilder p = new StringBuilder();
        p.append("WEBSITE SCAN — rendered in real Chromium (JS executed), data is live\n");
        p.append("finalUrl: ").append(r.finalUrl.isEmpty() ? r.askedUrl : r.finalUrl).append("\n");
        p.append("host: ").append(host).append(" tld: ").append(tld).append("\n");
        p.append("title: ").append(title).append("\nsiteName: ").append(siteName).append("\ndescription: ").append(Util.clip(desc, 200)).append("\n");
        p.append("security: https=").append(usesHttps).append(" validCert=").append(usesHttps && sslValid)
                .append(" sslErrors=").append(r.sslErrors).append(" httpErrors=").append(r.httpErrors)
                .append(" redirectHosts=").append(r.redirectHosts).append("\n");
        p.append("content: forms=").append(forms).append(" passwordFields=").append(pwFields)
                .append(" externalLinks=").append(externalLinks).append(" obfuscation=").append(obf).append("\n");
        if (!extScripts.isEmpty()) p.append("externalScripts: ").append(Util.clip(String.join("  ", extScripts), 700)).append("\n");
        if (!iframes.isEmpty()) p.append("iframes: ").append(Util.clip(String.join("  ", iframes), 400)).append("\n");
        if (!extRes.isEmpty()) p.append("externalResourcesLoaded(").append(extRes.size()).append("): ")
                .append(Util.clip(String.join("  ", extRes), 900)).append("\n");
        if (!r.console.isEmpty()) p.append("console: ").append(Util.clip(String.join("  ", r.console), 400)).append("\n");
        p.append("heuristics: hostIsIp=").append(hostIsIp).append(" punycode=").append(punycode)
                .append(" manySub=").append(manySub).append(" suspTld=").append(suspTld)
                .append(" shortener=").append(shortener).append(" brandKeywords=").append(brandWordsInHost)
                .append(" loginOverHttp=").append(loginOnHttp).append(" crossRedirect=").append(crossRedirect)
                .append(" riskScore=").append(risk).append("\n");
        p.append("visualScreenshotProvided: ").append(hasShot).append(" (use vision to judge if the page LOOKS like a fake/brand-impersonation login)\n");

        return new String[]{ev.toString(), p.toString()};
    }
}
