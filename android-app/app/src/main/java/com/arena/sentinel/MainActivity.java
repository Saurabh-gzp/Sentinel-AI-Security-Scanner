package com.arena.sentinel;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public class MainActivity extends Activity {

    private static final int REQ_APK = 7011;

    private View tabApp, tabWeb, tabSettings;
    private View navApp, navWeb, navSettings;
    private View navAppIcon, navWebIcon, navSettingsIcon;
    private TextView navAppText, navWebText, navSettingsText;
    private TextView modeIndicator;

    // app tab
    private View pickApk;
    private TextView apkFileName, appScanBtn, appStatusText;
    private View appStatus;
    private File apkFile;
    private Uri pickedUri;

    // web tab
    private android.widget.EditText urlInput;
    private TextView webScanBtn, webStatusText;
    private View webStatus;

    // settings tab
    private android.widget.EditText apiInput;
    private TextView saveKeyBtn, toggleKeyVis, loadModelsBtn, modelStatus, clearTempBtn;
    private LinearLayout modelList;
    private List<GeminiClient.ModelInfo> loadedModels;
    private String selectedModelId;

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        setContentView(R.layout.activity_main);

        modeIndicator = findViewById(R.id.modeIndicator);
        modeIndicator.setText(Util.modeLabel(this));

        applyInsets(findViewById(R.id.rootLayout),
                findViewById(R.id.appHeader), findViewById(R.id.appBottomNav));

        tabApp = findViewById(R.id.tabApp);
        tabWeb = findViewById(R.id.tabWeb);
        tabSettings = findViewById(R.id.tabSettings);

        navApp = findViewById(R.id.navApp); navWeb = findViewById(R.id.navWeb); navSettings = findViewById(R.id.navSettings);
        navAppIcon = findViewById(R.id.navAppIcon); navWebIcon = findViewById(R.id.navWebIcon); navSettingsIcon = findViewById(R.id.navSettingsIcon);
        navAppText = findViewById(R.id.navAppText); navWebText = findViewById(R.id.navWebText); navSettingsText = findViewById(R.id.navSettingsText);

        navApp.setOnClickListener(v -> showTab(0));
        navWeb.setOnClickListener(v -> showTab(1));
        navSettings.setOnClickListener(v -> showTab(2));

        setupAppTab();
        setupWebTab();
        setupSettingsTab();

        showTab(0);

        // open-gate: probe internet in background; popup if offline
        ensureInternet(() -> {});
    }

    private void showTab(int i) {
        tabApp.setVisibility(i == 0 ? View.VISIBLE : View.GONE);
        tabWeb.setVisibility(i == 1 ? View.VISIBLE : View.GONE);
        tabSettings.setVisibility(i == 2 ? View.VISIBLE : View.GONE);
        applyNav(i);
    }

    private void applyNav(int active) {
        applyNavIcon(navAppIcon, navAppText, active == 0);
        applyNavIcon(navWebIcon, navWebText, active == 1);
        applyNavIcon(navSettingsIcon, navSettingsText, active == 2);
    }

    private void applyNavIcon(View icon, TextView text, boolean on) {
        int color = getResources().getColor(on ? R.color.coral : R.color.nav_inactive);
        ((android.widget.ImageView) icon).setColorFilter(color);
        text.setTextColor(color);
    }

    // ---------------- APP TAB ----------------
    private void setupAppTab() {
        pickApk = tabApp.findViewById(R.id.pickApk);
        apkFileName = tabApp.findViewById(R.id.apkFileName);
        appScanBtn = tabApp.findViewById(R.id.appScanBtn);
        appStatus = tabApp.findViewById(R.id.appStatus);
        appStatusText = tabApp.findViewById(R.id.appStatusText);

        pickApk.setOnClickListener(v -> {
            String[] options = {"Storage \u2014 APK / APKS / XAPK file", "Phone \u2014 Installed apps"};
            new AlertDialog.Builder(this)
                .setTitle("Scan source")
                .setItems(options, (d, which) -> {
                    if (which == 0) {
                        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");
                        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                                "application/vnd.android.package-archive", "application/zip",
                                "application/xapk", "application/vnd.apkm", "application/octet-stream"});
                        try { startActivityForResult(i, REQ_APK); }
                        catch (Exception e) { Util.toast(this, "No file picker available"); }
                    } else {
                        startActivity(new Intent(this, AppListActivity.class));
                    }
                })
                .show();
        });

        appScanBtn.setOnClickListener(v -> startAppScan());
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_APK && res == RESULT_OK && data != null && data.getData() != null) {
            // pick must be INSTANT — do NOT copy here (that froze the UI). Copy on Scan, in background.
            pickedUri = data.getData();
            String name = displayName(pickedUri);
            apkFileName.setText(name != null ? name : "selected.apk");
            apkFile = null;
        }
    }

    private void startAppScan() { ensureInternet(() -> ensureKeyThen(this::doAppScan)); }

    private void doAppScan() {
        if (pickedUri == null) { Util.toast(this, R.string.err_no_file); return; }
        final String key = Prefs.getKey(this);
        final String model = Prefs.getModel(this);
        if (key.isEmpty()) { Util.toast(this, R.string.err_no_key); showTab(2); return; }
        if (model.isEmpty()) { Util.toast(this, R.string.err_no_model); showTab(2); return; }

        setAppStatus(true, "Reading package…");
        appScanBtn.setEnabled(false);
        final Uri uri = pickedUri;

        new Thread(() -> {
            try {
                // 1) copy picked file (apk / apks / xapk) in BACKGROUND — no UI freeze
                File pkg = copyToCache(uri, "pkg.bin");
                if (pkg == null) throw new Exception("could not read the file");
                // 2) open container (auto-detect apk/apks/xapk; extract base apk; list OBB)
                File workDir = new File(getCacheDir(), "extract");
                if (workDir.exists()) deleteRecursive(workDir);
                runUi(() -> appStatusText.setText("Opening package (apk/apks/xapk)…"));
                PackageOpener.Opened opened = PackageOpener.open(pkg, workDir);
                if (opened.baseApk == null)
                    throw new Exception(opened.error == null ? "could not open the package" : opened.error);
                // 3) AGENTIC scan — Gemini uses tools to decide what/how to scan
                AppAgent.Progress prog = msg -> runUi(() -> appStatusText.setText(msg));
                ScanReport rep = AppAgent.run(key, model, opened, getPackageManager(), prog);
                ReportActivity.LAST = rep;
                cleanupTemp();
                runUi(() -> {
                    setAppStatus(false, null);
                    appScanBtn.setEnabled(true);
                    startActivity(new Intent(this, ReportActivity.class));
                });
            } catch (Exception e) {
                final String msg = friendly(e);
                if (msg.startsWith("API")) Prefs.setKeyVerified(this, false);
                cleanupTemp();
                runUi(() -> {
                    setAppStatus(false, null);
                    appScanBtn.setEnabled(true);
                    Util.toast(this, "Scan failed: " + msg);
                });
            }
        }).start();
    }

    private void setAppStatus(boolean on, String text) {
        appStatus.setVisibility(on ? View.VISIBLE : View.GONE);
        if (text != null) appStatusText.setText(text);
    }

    // ---------------- WEB TAB ----------------
    private void setupWebTab() {
        urlInput = tabWeb.findViewById(R.id.urlInput);
        webScanBtn = tabWeb.findViewById(R.id.webScanBtn);
        webStatus = tabWeb.findViewById(R.id.webStatus);
        webStatusText = tabWeb.findViewById(R.id.webStatusText);
        webScanBtn.setOnClickListener(v -> startWebScan());
    }

    private void startWebScan() { ensureInternet(() -> ensureKeyThen(this::doWebScan)); }

    private void doWebScan() {
        final String raw = urlInput.getText().toString().trim();
        if (raw.isEmpty()) { Util.toast(this, R.string.err_no_url); return; }
        final String key = Prefs.getKey(this);
        final String model = Prefs.getModel(this);
        if (key.isEmpty()) { Util.toast(this, R.string.err_no_key); showTab(2); return; }
        if (model.isEmpty()) { Util.toast(this, R.string.err_no_model); showTab(2); return; }

        final String normUrl = WebAnalyzer.normalize(raw);
        int si = normUrl.indexOf("://");
        if (si > 0) {
            String sch = normUrl.substring(0, si).toLowerCase();
            if (!sch.equals("http") && !sch.equals("https")) { finishNonWeb(normUrl, sch); return; }
        }

        setWebStatus(true, "Checking redirect chain and server…");
        webScanBtn.setEnabled(false);

        new Thread(() -> {
            final WebProbe.Result probe = WebProbe.run(normUrl);
            runUi(() -> {
                setWebStatus(true, "Rendering page in Chromium…");
                WebRender.render(this, normUrl, 12000L, render -> {
                    setWebStatus(true, "Deep AI analysis…");
                    if ((probe.html == null || probe.html.isEmpty()) && render.renderedHtml != null)
                        probe.html = render.renderedHtml;
                    final WebEngine.Report eng = WebEngine.analyze(probe);
                    new Thread(() -> {
                        try {
                            String aiPayload = buildWebAIPayload(eng, probe, render);
                            String resp = GeminiClient.generateAuto(key, model, ScanReport.webPrompt(aiPayload), render.screenshot);
                            ScanReport rep = ScanReport.parse(resp);
                            rep.verdict = mapVerdict(eng.verdict);   // FORCE engine verdict — no hedging
                            rep.evidence = buildWebEvidence(probe, render, eng);
                            rep.target = probe.finalUrl.isEmpty() ? normUrl : probe.finalUrl;
                            rep.type = "Website Scan";
                            injectEngineRisks(rep, eng);
                            if (rep.summary == null || rep.summary.trim().isEmpty())
                                rep.summary = "Engine verdict: " + eng.verdict + (eng.reasons.isEmpty() ? "" : ". " + eng.reasons.get(0));
                            ReportActivity.LAST = rep;
                            cleanupTemp();
                            runUi(() -> {
                                setWebStatus(false, null);
                                webScanBtn.setEnabled(true);
                                startActivity(new Intent(this, ReportActivity.class));
                            });
                } catch (Exception e) {
                    final String msg = friendly(e);
                    if (msg.startsWith("API")) Prefs.setKeyVerified(this, false);
                    runUi(() -> {
                        setWebStatus(false, null);
                        webScanBtn.setEnabled(true);
                        Util.toast(this, "Scan failed: " + msg);
                    });
                }
                    }).start();
                });
            });
        }).start();
    }

    private void finishNonWeb(String url, String sch) {
        ScanReport rep = new ScanReport();
        rep.verdict = ScanReport.SAFE;
        rep.confidence = 60;
        rep.summary = "This is a '" + sch + "' link, not a website — there is nothing to scan.";
        rep.recommendation = "A web scan is not needed for a " + sch + " link.";
        rep.target = url;
        rep.type = "Website Scan";
        rep.evidence = "Link: " + url + "\nType: " + sch + ": (non-web)";
        ReportActivity.LAST = rep;
        startActivity(new Intent(this, ReportActivity.class));
    }

    private int mapVerdict(String v) {
        if (v == null) return ScanReport.SUSPICIOUS;
        String l = v.toLowerCase();
        if (l.contains("malic")) return ScanReport.MALICIOUS;
        if (l.contains("susp")) return ScanReport.SUSPICIOUS;
        if (l.contains("safe") || l.contains("clean")) return ScanReport.SAFE;
        return ScanReport.SUSPICIOUS;
    }

    private void injectEngineRisks(ScanReport rep, WebEngine.Report eng) {
        if (!rep.risks.isEmpty() || eng.reasons.isEmpty()) return;
        String sev = eng.verdict.equals("Malicious") ? "High" : (eng.verdict.equals("Suspicious") ? "Medium" : "Low");
        for (String r : eng.reasons) rep.risks.add(new ScanReport.Risk("Rule engine finding", sev, r));
    }

    private String buildWebAIPayload(WebEngine.Report eng, WebProbe.Result p, WebRender.Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append("ENGINE VERDICT: ").append(eng.verdict).append("\nCONCRETE REASONS:\n");
        for (String x : eng.reasons) sb.append("- ").append(x).append("\n");
        sb.append("finalUrl: ").append(p.finalUrl).append("\nhost: ").append(eng.host)
                .append("  server: ").append(p.server).append("\n");
        sb.append("sslOk: ").append(p.sslOk).append("  sslInfo: ").append(p.sslinfo).append("\nredirectChain:\n");
        for (String h : p.hops) sb.append("  ").append(h).append("\n");
        sb.append("title: ").append(eng.title).append("\nforms: ").append(eng.forms)
                .append("  passwordFields: ").append(eng.pw).append("\n");
        if (!eng.scripts.isEmpty()) sb.append("scripts: ").append(Util.clip(String.join("  ", eng.scripts), 500)).append("\n");
        if (!eng.iframes.isEmpty()) sb.append("iframes: ").append(Util.clip(String.join("  ", eng.iframes), 300)).append("\n");
        if (r != null) {
            sb.append("visualScreenshotAttached: ").append(r.screenshot != null).append("\n");
            if (!r.requests.isEmpty()) sb.append("resourcesLoadedByBrowser: ").append(r.requests.size()).append("\n");
        }
        return sb.toString();
    }

    private String buildWebEvidence(WebProbe.Result p, WebRender.Result r, WebEngine.Report eng) {
        StringBuilder ev = new StringBuilder();
        ev.append("ENGINE VERDICT: ").append(eng.verdict).append("\n\nCONCRETE PROOF (rule engine):\n");
        if (eng.reasons.isEmpty()) ev.append("  (no concrete red flag found)\n");
        for (String x : eng.reasons) ev.append("  • ").append(x).append("\n");
        ev.append("\nHOST: ").append(eng.host).append("   SERVER: ").append(p.server)
                .append("\nSSL: ").append(p.sslOk ? "valid" : "INVALID — " + Util.clip(p.sslinfo, 100)).append("\n");
        ev.append("\nREDIRECT CHAIN:\n");
        for (String h : p.hops) ev.append("  ").append(h).append("\n");
        if (!eng.title.isEmpty()) ev.append("\nTITLE: ").append(eng.title).append("\n");
        ev.append("FORMS: ").append(eng.forms).append("   PASSWORD FIELDS: ").append(eng.pw).append("\n");
        if (!eng.scripts.isEmpty()) { ev.append("SCRIPTS:\n"); for (String s : eng.scripts) ev.append("  ").append(Util.clip(s, 110)).append("\n"); }
        if (!eng.iframes.isEmpty()) { ev.append("IFRAMES:\n"); for (String s : eng.iframes) ev.append("  ").append(Util.clip(s, 110)).append("\n"); }
        if (r != null) {
            if (!r.requests.isEmpty()) {
                ev.append("\nRESOURCES LOADED BY BROWSER (").append(r.requests.size()).append("):\n");
                int c = 0;
                for (String u : r.requests) { ev.append("  ").append(Util.clip(u, 110)).append("\n"); if (++c >= 12) break; }
            }
            ev.append("\nVision screenshot: ").append(r.screenshot != null ? "captured (AI vision use kiya)" : "n/a").append("\n");
            if (!r.nonHttpNavigations.isEmpty()) {
                ev.append("\nNON-HTTP REDIRECTS (mobile phishing evasion):\n");
                for (String n : r.nonHttpNavigations) ev.append("  ").append(Util.clip(n, 110)).append("\n");
            }
        }
        boolean noContent = (p.html == null || p.html.isEmpty()) && (r == null || r.renderedHtml == null || r.renderedHtml.isEmpty());
        if (noContent) {
            ev.append("\nNOTE: this URL's page content could not be fetched in the browser — it uses a mobile-intent / server-side redirect that does not open in a normal browser. The rule engine still reached a definitive verdict from the redirect chain and patterns.\n");
        }
        return ev.toString();
    }

    private void setWebStatus(boolean on, String text) {
        webStatus.setVisibility(on ? View.VISIBLE : View.GONE);
        if (text != null) webStatusText.setText(text);
    }

    // ---------------- SETTINGS TAB ----------------
    private void setupSettingsTab() {
        apiInput = tabSettings.findViewById(R.id.apiInput);
        saveKeyBtn = tabSettings.findViewById(R.id.saveKeyBtn);
        toggleKeyVis = tabSettings.findViewById(R.id.toggleKeyVisibility);
        loadModelsBtn = tabSettings.findViewById(R.id.loadModelsBtn);
        modelList = tabSettings.findViewById(R.id.modelList);
        modelStatus = tabSettings.findViewById(R.id.modelStatus);
        clearTempBtn = tabSettings.findViewById(R.id.clearTempBtn);

        apiInput.setText("");
        apiInput.setHint("API key saved securely — enter a new key to replace it");
        selectedModelId = Prefs.getModel(this);
        refreshModelStatus();

        saveKeyBtn.setOnClickListener(v -> {
            String k = apiInput.getText().toString().trim();
            Prefs.setKey(this, k); // resets verified
            if (k.isEmpty()) { Util.toast(this, "API key cleared"); return; }
            Util.toast(this, "Verifying API key…");
            saveKeyBtn.setEnabled(false);
            new Thread(() -> {
                final boolean online = Util.online(this);
                final boolean ok = online && GeminiClient.validateKey(k);
                runUi(() -> {
                    saveKeyBtn.setEnabled(true);
                    if (!online) Util.toast(this, "No internet — could not verify key. Turn on internet and Save again.");
                    else if (ok) { Prefs.setKeyVerified(this, true); Util.toast(this, "API key is valid"); }
                    else Util.toast(this, "API key is invalid or not working. Please check.");
                });
            }).start();
        });

        toggleKeyVis.setOnClickListener(v -> {
            boolean hidden = (apiInput.getInputType() & InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_PASSWORD;
            apiInput.setInputType(hidden ? (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
                    : (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD));
        });

        loadModelsBtn.setOnClickListener(v -> loadModels());
        clearTempBtn.setOnClickListener(v -> {
            int n = cleanupTemp();
            Util.toast(this, n > 0 ? "Deleted " + n + " temp file(s)" : "Nothing to clean");
        });

        tabSettings.findViewById(R.id.howToCreateKeyBtn).setOnClickListener(v ->
                startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://youtu.be/9-Pbgl4B9Uw?si=yBQ5_P6CcgpSn8px"))));

        tabSettings.findViewById(R.id.linkWebsite).setOnClickListener(v ->
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://saurabh-gzp.github.io/Sentinel-AI-Security-Scanner/"))));
        tabSettings.findViewById(R.id.linkGithub).setOnClickListener(v ->
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/Saurabh-gzp/Sentinel-AI-Security-Scanner"))));
    }

    private void loadModels() {
        final String key = Prefs.getKey(this);
        if (key.isEmpty()) { Util.toast(this, R.string.err_no_key); return; }
        loadModelsBtn.setText("Loading…");
        loadModelsBtn.setEnabled(false);
        new Thread(() -> {
            try {
                List<GeminiClient.ModelInfo> models = GeminiClient.listModels(key);
                loadedModels = models;
                runUi(() -> {
                    loadModelsBtn.setText(R.string.load_models);
                    loadModelsBtn.setEnabled(true);
                    renderModelList();
                    if (models.isEmpty()) Util.toast(this, "No usable models found");
                });
            } catch (Exception e) {
                final String msg = friendly(e);
                runUi(() -> {
                    loadModelsBtn.setText(R.string.load_models);
                    loadModelsBtn.setEnabled(true);
                    Util.toast(this, "Load failed: " + msg);
                });
            }
        }).start();
    }

    private void renderModelList() {
        modelList.removeAllViews();
        if (loadedModels == null) return;
        for (GeminiClient.ModelInfo m : loadedModels) {
            final String id = m.id;
            View row = buildModelRow(m.name, id.equals(selectedModelId));
            row.setOnClickListener(v -> {
                selectedModelId = id;
                Prefs.setModel(this, id);
                renderModelList();
                refreshModelStatus();
            });
            modelList.addView(row);
        }
    }

    private View buildModelRow(String name, boolean selected) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        int pad = dp(14);
        row.setPadding(pad, dp(12), pad, dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(8);
        row.setLayoutParams(lp);
        row.setBackgroundResource(selected ? R.drawable.bg_button_primary : R.drawable.bg_button_ghost);

        TextView dot = new TextView(this);
        dot.setText(selected ? "●" : "○");
        dot.setTextColor(getResources().getColor(selected ? R.color.surface : R.color.coral));
        dot.setTextSize(14);
        row.addView(dot);

        TextView t = new TextView(this);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        tp.leftMargin = dp(12);
        t.setLayoutParams(tp);
        t.setText(name);
        t.setTextSize(15);
        t.setTextColor(getResources().getColor(selected ? R.color.surface : R.color.ink));
        row.addView(t);

        if (selected) {
            TextView tag = new TextView(this);
            tag.setText("ACTIVE");
            tag.setTextSize(10);
            tag.setTextColor(getResources().getColor(R.color.surface));
            row.addView(tag);
        }
        return row;
    }

    private void refreshModelStatus() {
        modelStatus.setText("Current model:\n" + (selectedModelId == null ? "none" : selectedModelId.replace("models/", "")));
    }

    // ---------------- helpers ----------------
    private void runUi(Runnable r) { runOnUiThread(r); }

    /** Edge-to-edge (targetSdk 36): push content below status bar, above gesture nav. */
    private void applyInsets(View root, final View header, final View nav) {
        if (root == null) return;
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            int top = insets.getSystemWindowInsetTop();
            int bot = insets.getSystemWindowInsetBottom();
            if (header != null) header.setPadding(dp(20), top + dp(4), dp(20), dp(6));
            if (nav != null) nav.setPadding(0, dp(10), 0, bot + dp(6));
            return insets;
        });
        root.requestApplyInsets();
    }

    // ---------------- internet gate ----------------
    private AlertDialog netDialog;
    private Runnable afterNet;

    /** Proceed with onConnected only when real internet is available (background probe). */
    private void ensureInternet(final Runnable onConnected) {
        afterNet = onConnected;
        new Thread(() -> {
            final boolean online = Util.online(MainActivity.this);
            runUi(() -> {
                if (online) { Runnable r = afterNet; afterNet = null; if (r != null) r.run(); }
                else showNetDialog();
            });
        }).start();
    }

    private void showNetDialog() {
        if (netDialog != null && netDialog.isShowing()) return;
        netDialog = new AlertDialog.Builder(this)
                .setTitle("No internet connection")
                .setMessage("An internet connection is required to scan.\nPlease turn on Wi-Fi or mobile data, then tap Check.\n\nThis popup closes automatically once the internet is back.")
                .setCancelable(false)
                .setPositiveButton("Check", null)
                .create();
        netDialog.show();
        netDialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            Util.toast(MainActivity.this, "Checking connection…");
            new Thread(() -> {
                final boolean online = Util.online(MainActivity.this);
                runUi(() -> {
                    if (online) {
                        if (netDialog != null && netDialog.isShowing()) netDialog.dismiss();
                        if (afterNet != null) { Runnable r = afterNet; afterNet = null; r.run(); }
                    } else {
                        Util.toast(MainActivity.this, "Still no internet connection");
                    }
                });
            }).start();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (AppListActivity.shouldOpenSettings) {
            AppListActivity.shouldOpenSettings = false;
            showTab(2);
        }
        // auto-recover: if the no-internet popup is up, re-probe; close it once internet returns
        if (netDialog != null && netDialog.isShowing()) {
            new Thread(() -> {
                final boolean online = Util.online(MainActivity.this);
                if (online) runUi(() -> {
                    if (netDialog != null && netDialog.isShowing()) netDialog.dismiss();
                    if (afterNet != null) { Runnable r = afterNet; afterNet = null; r.run(); }
                });
            }).start();
        }
    }

    /** API-key gate: verified ONCE per key (not on every scan). */
    private void ensureKeyThen(final Runnable onOk) {
        final String key = Prefs.getKey(this);
        if (key.isEmpty()) { Util.toast(this, "Please add your Gemini API key in Settings first"); showTab(2); return; }
        if (Prefs.isKeyVerified(this)) { onOk.run(); return; }
        Util.toast(this, "Verifying API key (first time only)…");
        new Thread(() -> {
            final boolean ok = GeminiClient.validateKey(key);
            runUi(() -> {
                if (ok) { Prefs.setKeyVerified(this, true); onOk.run(); }
                else { Prefs.setKeyVerified(this, false); Util.toast(this, "API key is invalid or not working. Add a valid key in Settings."); showTab(2); }
            });
        }).start();
    }

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }

    private String friendly(Exception e) {
        String m = e.getMessage() == null ? e.toString() : e.getMessage();
        if (m.length() > 300) m = m.substring(0, 300);
        return m;
    }

    private String displayName(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null);
            if (c != null && c.moveToFirst()) return c.getString(0);
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        return uri.getLastPathSegment();
    }

    private File copyToCache(Uri uri, String name) {
        try {
            File f = new File(getCacheDir(), name);
            InputStream in = getContentResolver().openInputStream(uri);
            OutputStream out = new java.io.FileOutputStream(f);
            byte[] b = new byte[16384];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            in.close();
            out.close();
            return f;
        } catch (Exception e) {
            return null;
        }
    }

    private int cleanupTemp() {
        int n = 0;
        try {
            File c = getCacheDir();
            File[] fs = c.listFiles();
            if (fs != null) for (File f : fs) {
                String nm = f.getName();
                if (nm.endsWith(".apk") || nm.startsWith("scan") || nm.startsWith("web") || nm.startsWith("extract")) {
                    if (deleteRecursive(f)) n++;
                }
            }
        } catch (Exception ignored) { }
        return n;
    }

    private boolean deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) deleteRecursive(c);
        }
        return f.delete();
    }
}
