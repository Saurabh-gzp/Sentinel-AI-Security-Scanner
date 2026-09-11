package com.arena.sentinel;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;

/** Server-side redirect-chain probe (no auto-follow). Captures every hop incl.
 *  non-http schemes (intent://, data:) and SSL problems — the smoking gun for
 *  mobile phishing. Runs on a background thread. */
class WebProbe {

    static class Result {
        String askedUrl = "";
        String finalUrl = "";
        String host = "";
        String html = "";
        String server = "";
        String sslinfo = "";
        boolean sslOk = true;
        boolean reached = false;
        boolean hasIntent = false;
        boolean hasNonHttp = false;
        boolean failed = false;
        List<String> hops = new ArrayList<>();     // human: "301  url"
        List<String> hopUrls = new ArrayList<>();  // raw urls visited
    }

    private static final String UA = "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 SentinelScan/1.0";

    static Result run(String start) {
        Result r = new Result();
        r.askedUrl = start;
        String cur = start.contains("://") ? start : "https://" + start;
        try { r.host = new URL(cur).getHost().toLowerCase(); } catch (Exception ignored) { }

        for (int i = 0; i < 8; i++) {
            HttpURLConnection c = null;
            try {
                URL u = new URL(cur);
                if (isPrivateHost(u.getHost())) {
                    r.failed = true;
                    r.finalUrl = cur;
                    r.hops.add("BLOCKED-PRIVATE-HOST  " + cur);
                    break;
                }
                c = (HttpURLConnection) u.openConnection();
                c.setInstanceFollowRedirects(false);
                c.setConnectTimeout(16000);
                c.setReadTimeout(20000);
                c.setRequestMethod("GET");
                c.setRequestProperty("User-Agent", UA);
                c.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*");
                int code = c.getResponseCode();
                r.server = nz(c.getHeaderField("Server"));
                String ctype = nz(c.getContentType());
                r.hopUrls.add(cur);
                if (c instanceof HttpsURLConnection) {
                    try {
                        java.security.cert.Certificate[] certs = ((HttpsURLConnection) c).getServerCertificates();
                        if (certs != null && certs.length > 0 && certs[0] instanceof java.security.cert.X509Certificate) {
                            java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) certs[0];
                            r.sslinfo = "issuer=" + x.getIssuerX500Principal().getName() + "; expires=" + x.getNotAfter();
                        }
                    } catch (Exception ignore) { }
                }
                boolean redir = code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
                if (redir) {
                    String loc = c.getHeaderField("Location");
                    r.hops.add(code + "  " + cur);
                    if (loc == null || loc.isEmpty()) { r.finalUrl = cur; break; }
                    String low = loc.toLowerCase();
                    if (loc.contains("://") && !low.startsWith("http://") && !low.startsWith("https://")) {
                        r.hasNonHttp = true;
                        if (low.startsWith("intent:") || low.contains("package=") || low.contains("scheme=")) r.hasIntent = true;
                        r.hops.add("NON-HTTP  " + loc);
                        r.finalUrl = loc;
                        break;
                    }
                    String nxt = new URL(u, loc).toString();
                    cur = nxt;
                    continue;
                }
                // final response
                r.reached = true;
                r.finalUrl = cur;
                r.hops.add(code + "  " + cur);
                if (ctype.toLowerCase().contains("text")) {
                    InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
                    r.html = readUpTo(in, 200000);
                }
                break;
            } catch (SSLException e) {
                r.sslOk = false;
                r.sslinfo = nz(e.getMessage());
                r.hops.add("SSL-ERR  " + cur);
                r.finalUrl = cur;
                break;
            } catch (Exception e) {
                String m = e.getMessage() == null ? e.toString() : e.getMessage();
                if (m.contains("SSL") || m.toLowerCase().contains("cert")) { r.sslOk = false; r.sslinfo = m; }
                r.hops.add("ERR  " + cur + "  " + m.substring(0, Math.min(80, m.length())));
                if (i == 0) {
                    // try http:// fallback once if it was an https attempt on a bare host
                    if (!start.contains("://")) { cur = "http://" + start; continue; }
                    r.failed = true;
                }
                r.finalUrl = cur;
                break;
            } finally {
                if (c != null) c.disconnect();
            }
        }
        try { r.host = new URL(r.finalUrl.isEmpty() ? cur : r.finalUrl).getHost().toLowerCase(); } catch (Exception ignored) { }
        return r;
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

    private static boolean isPrivateHost(String host) {
        try {
            if (host == null || host.isEmpty()) return true;
            for (InetAddress a : InetAddress.getAllByName(host)) {
                if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                        || a.isSiteLocalAddress() || a.isMulticastAddress()) return true;
            }
            return false;
        } catch (Exception e) { return true; }
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
