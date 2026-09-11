package com.arena.sentinel;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.net.http.SslError;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.ConsoleMessage;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.json.JSONArray;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real headless Chromium (WebView) render: executes JS, captures all requests,
 *  SSL errors, console, rendered DOM and a screenshot for Gemini vision. */
class WebRender {

    interface Callback { void onDone(Result r); }

    static class Result {
        String askedUrl = "";
        String finalUrl = "";
        String title = "";
        String renderedHtml = "";
        String scheme = "";
        boolean isNonWeb = false;
        Set<String> requests = new LinkedHashSet<>();
        Set<String> redirectHosts = new LinkedHashSet<>();
        Set<String> sslErrors = new LinkedHashSet<>();
        Set<String> httpErrors = new LinkedHashSet<>();
        Set<String> console = new LinkedHashSet<>();
        Set<String> nonHttpNavigations = new LinkedHashSet<>();
        byte[] screenshot = null;
        String error = "";
    }

    static void render(final Activity act, final String url, final long timeoutMs, final Callback cb) {
        final Result r = new Result();
        r.askedUrl = url;
        r.finalUrl = url;
        int s = url.indexOf("://");
        if (s > 0) r.scheme = url.substring(0, s).toLowerCase();
        // non-browsable link (mailto:, tel:, intent:, whatsapp:, etc.) — accept but skip render
        if (s > 0 && !r.scheme.equals("http") && !r.scheme.equals("https")) {
            r.isNonWeb = true;
            r.error = "Non-web link type (" + r.scheme + ":). Cannot render a page.";
            cb.onDone(r);
            return;
        }
        if (isPrivateHost(url)) {
            r.error = "Private or local network address blocked for safety.";
            cb.onDone(r);
            return;
        }

        final WebView wv;
        try {
            wv = new WebView(act);
        } catch (Exception e) {
            r.error = "WebView unavailable: " + e.getMessage();
            cb.onDone(r);
            return;
        }
        wv.setLayerType(View.LAYER_TYPE_SOFTWARE, null);
        WebSettings ws = wv.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setJavaScriptCanOpenWindowsAutomatically(false);
        ws.setSupportZoom(false);
        ws.setLoadWithOverviewMode(true);
        ws.setUseWideViewPort(true);
        ws.setMediaPlaybackRequiresUserGesture(false);
        ws.setBlockNetworkImage(false);

        final AtomicBoolean finished = new AtomicBoolean(false);
        final Handler h = new Handler(Looper.getMainLooper());

        wv.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest req) {
                android.net.Uri uri = req.getUrl();
                String sch = uri.getScheme();
                if (sch == null || (!sch.equals("http") && !sch.equals("https"))) {
                    // intent:/data:/javascript: etc. — mobile phishing evasion. Block + record.
                    r.nonHttpNavigations.add(String.valueOf(uri));
                    return true;
                }
                if (isPrivateHost(uri.toString())) {
                    r.nonHttpNavigations.add("blocked-private-host:" + uri);
                    return true;
                }
                addHost(r.redirectHosts, uri);
                return false;
            }
            @Override public void onPageFinished(WebView v, String u) {
                r.finalUrl = u;
                String t = v.getTitle();
                r.title = t == null ? "" : t;
                h.postDelayed(() -> capture(act, wv, r, finished, cb, h), 1000);
            }
            @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) {
                r.sslErrors.add(sslText(error));
                handler.cancel(); // never execute content with an invalid certificate
            }
            @Override public void onReceivedHttpError(WebView v, WebResourceRequest req, WebResourceResponse resp) {
                if (req.isForMainFrame()) r.httpErrors.add("HTTP " + resp.getStatusCode() + " " + req.getUrl());
            }
            @Override public void onReceivedError(WebView v, WebResourceRequest req, WebResourceError err) {
                if (req.isForMainFrame()) r.httpErrors.add("LOAD-ERR " + err.getDescription() + " " + req.getUrl());
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest req) {
                String u = String.valueOf(req.getUrl());
                if (r.requests.size() < 120) r.requests.add(u);
                return null;
            }
        });

        wv.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onConsoleMessage(ConsoleMessage cm) {
                if (r.console.size() < 25) r.console.add(cm.message());
                return true;
            }
            @Override public boolean onCreateWindow(WebView v, boolean d, boolean u, android.os.Message m) { return false; }
        });

        // build container + scrim
        final FrameLayout root = (FrameLayout) act.findViewById(android.R.id.content);
        final FrameLayout container = new FrameLayout(act);
        container.setLayoutParams(new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        wv.setLayoutParams(new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        container.addView(wv);
        container.addView(buildScrim(act));
        root.addView(container);

        try {
            wv.loadUrl(url);
        } catch (Exception e) {
            r.error = "load failed: " + e.getMessage();
            root.removeView(container);
            cb.onDone(r);
            return;
        }
        // global timeout
        h.postDelayed(() -> capture(act, wv, r, finished, cb, h), timeoutMs);
    }

    private static void capture(final Activity act, final WebView wv, final Result r,
                                final AtomicBoolean finished, final Callback cb, final Handler h) {
        if (finished.getAndSet(true)) return;
        try {
            wv.evaluateJavascript(
                    "(function(){try{return (document.documentElement.outerHTML||'').slice(0,24000);}catch(e){return '';}})()",
                    value -> {
                        if (value != null && !value.equals("null")) {
                            try { r.renderedHtml = new JSONArray("[" + value + "]").getString(0); }
                            catch (Exception e) { r.renderedHtml = value; }
                        }
                        r.screenshot = captureBitmap(wv);
                        h.post(() -> cleanup(act, wv, r, cb));
                    });
        } catch (Exception e) {
            r.error = "capture failed: " + e.getMessage();
            cleanup(act, wv, r, cb);
        }
    }

    private static void cleanup(Activity act, final WebView wv, final Result r, final Callback cb) {
        try {
            View parent = (View) wv.getParent();
            if (parent instanceof ViewGroup) {
                ViewGroup container = (ViewGroup) parent;
                container.removeView(wv);
                View root = (View) container.getParent();
                if (root instanceof ViewGroup) ((ViewGroup) root).removeView(container);
            }
        } catch (Exception ignored) { }
        try { wv.destroy(); } catch (Exception ignored) { }
        cb.onDone(r);
    }

    private static byte[] captureBitmap(WebView wv) {
        try {
            int w = wv.getWidth(), hh = wv.getHeight();
            if (w <= 0 || hh <= 0) return null;
            int maxH = 1600;
            if (hh > maxH) hh = maxH;
            Bitmap bmp = Bitmap.createBitmap(w, hh, Bitmap.Config.ARGB_8888);
            Canvas c = new Canvas(bmp);
            c.drawColor(Color.WHITE);
            wv.draw(c);
            if (isBlank(bmp)) { bmp.recycle(); return null; }
            int targetW = 768;
            float scale = w > targetW ? (float) targetW / w : 1f;
            int nw = (int) (w * scale), nh = (int) (hh * scale);
            Bitmap scaled = Bitmap.createScaledBitmap(bmp, nw, nh, true);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            scaled.compress(Bitmap.CompressFormat.JPEG, 70, bo);
            bmp.recycle(); scaled.recycle();
            byte[] data = bo.toByteArray();
            return data.length < 380000 ? data : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isBlank(Bitmap b) {
        int w = b.getWidth(), h = b.getHeight();
        int first = b.getPixel(w / 2, h / 2);
        for (int y = 0; y < h; y += Math.max(1, h / 12)) {
            for (int x = 0; x < w; x += Math.max(1, w / 12)) {
                if (b.getPixel(x, y) != first) return false;
            }
        }
        return true;
    }

    private static View buildScrim(Activity act) {
        FrameLayout scrim = new FrameLayout(act);
        scrim.setLayoutParams(new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        scrim.setBackgroundColor(0x00000000); // transparent -> the real page is visible behind
        LinearLayout bar = new LinearLayout(act);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(0xE6201E1A);
        bar.setPadding(dp(act, 16), statusBarHeight(act) + dp(act, 10), dp(act, 16), dp(act, 10));
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = Gravity.TOP;
        bar.setLayoutParams(lp);
        ProgressBar pb = new ProgressBar(act);
        pb.setIndeterminate(true);
        pb.getIndeterminateDrawable().setColorFilter(0xFFD97757, android.graphics.PorterDuff.Mode.SRC_IN);
        bar.addView(pb);
        TextView tv = new TextView(act);
        tv.setText("   Scanning page…");
        tv.setTextColor(0xFFFFFFFF);
        tv.setTextSize(14);
        bar.addView(tv);
        scrim.addView(bar);
        return scrim;
    }

    private static int statusBarHeight(Activity a) {
        int rid = a.getResources().getIdentifier("status_bar_height", "dimen", "android");
        return rid > 0 ? a.getResources().getDimensionPixelSize(rid) : dp(a, 24);
    }

    private static void addHost(Set<String> set, android.net.Uri u) {
        if (u == null) return;
        String host = u.getHost();
        if (host != null && !host.isEmpty()) set.add(host.toLowerCase());
    }

    private static boolean isPrivateHost(String rawUrl) {
        try {
            String host = android.net.Uri.parse(rawUrl).getHost();
            if (host == null || host.isEmpty()) return true;
            for (InetAddress a : InetAddress.getAllByName(host)) {
                if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                        || a.isSiteLocalAddress() || a.isMulticastAddress()) return true;
            }
            return false;
        } catch (Exception e) { return true; }
    }

    private static String sslText(SslError e) {
        if (e == null) return "SSL error";
        switch (e.getPrimaryError()) {
            case SslError.SSL_UNTRUSTED: return "Untrusted certificate (self-signed / bad CA)";
            case SslError.SSL_EXPIRED: return "Expired certificate";
            case SslError.SSL_NOTYETVALID: return "Certificate not yet valid";
            case SslError.SSL_IDMISMATCH: return "Hostname mismatch on certificate";
            case SslError.SSL_DATE_INVALID: return "Invalid certificate date";
            default: return "SSL error (" + e.getPrimaryError() + ")";
        }
    }

    private static int dp(Activity a, int v) { return (int) (v * a.getResources().getDisplayMetrics().density + 0.5f); }
}
