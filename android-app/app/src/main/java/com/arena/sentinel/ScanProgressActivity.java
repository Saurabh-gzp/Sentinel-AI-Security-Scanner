package com.arena.sentinel;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/** Live event log: every row is emitted only when the corresponding backend operation runs. */
public class ScanProgressActivity extends Activity {
    private LinearLayout eventList;
    private TextView status, detail;
    private ProgressBar spinner;
    private TextView current;
    private volatile boolean cancelled = false;

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s); setContentView(R.layout.activity_scan_progress);
        if (Prefs.getKey(this).isEmpty()) {
            AppListActivity.shouldOpenSettings = true;
            finish();
            return;
        }
        View root = findViewById(R.id.scanRoot);
        root.setOnApplyWindowInsetsListener((v, insets) -> { v.setPadding(dp(26), insets.getSystemWindowInsetTop() + dp(8), dp(26), insets.getSystemWindowInsetBottom() + dp(18)); return insets; }); root.requestApplyInsets();
        eventList = findViewById(R.id.eventList); status = findViewById(R.id.scanStatus); detail = findViewById(R.id.scanDetail); spinner = findViewById(R.id.scanProgress);
        findViewById(R.id.cancelScan).setOnClickListener(v -> { cancelled = true; finish(); });
        runScan(getIntent().getStringExtra("sourceDir"), getIntent().getStringExtra("appName"));
    }

    private void runScan(String source, String appName) {
        new Thread(() -> {
            File dest = new File(getCacheDir(), "installed.apk"); File work = new File(getCacheDir(), "extract");
            try {
                event("Copying installed APK", "Reading the selected app from its installed source");
                copy(new File(source), dest); checkCancelled();
                event("Opening package", "Inspecting APK container and package metadata");
                if (work.exists()) deleteRecursive(work); PackageOpener.Opened opened = PackageOpener.open(dest, work);
                if (opened.baseApk == null) throw new Exception("Could not open installed package"); checkCancelled();
                if (!Util.online(this)) throw new Exception("No internet connection");
                AppAgent.Progress prog = msg -> { if (!cancelled) event(msg, "Live callback from Sentinel agent"); };
                ScanReport rep = AppAgent.run(Prefs.getKey(this), Prefs.getModel(this), opened, getPackageManager(), prog);
                checkCancelled();
                event("Cleaning temporary files", "Removing copied APK and extracted package data"); deleteRecursive(work); dest.delete(); runOnUiThread(this::doneCurrent);
                ReportActivity.LAST = rep;
                runOnUiThread(() -> startActivity(new Intent(this, ReportActivity.class))); runOnUiThread(this::finish);
            } catch (Exception e) {
                deleteRecursive(work); dest.delete();
                if (!cancelled) runOnUiThread(() -> { spinner.setVisibility(View.GONE); status.setText("Scan stopped"); detail.setText(e.getMessage() == null ? "Please try again." : e.getMessage()); });
            }
        }).start();
    }

    private void event(String title, String subtitle) {
        runOnUiThread(() -> {
            doneCurrent();
            current = new TextView(this); current.setText("●  " + title + "\n    " + subtitle); current.setTextSize(14); current.setTextColor(getResources().getColor(R.color.ink)); current.setLineSpacing(0, 1.12f); current.setPadding(dp(14), dp(12), dp(14), dp(12));
            GradientDrawable bg = new GradientDrawable(); bg.setColor(getResources().getColor(R.color.surface_alt)); bg.setCornerRadius(dp(14)); current.setBackground(bg);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.topMargin = dp(9); eventList.addView(current, lp); current.setAlpha(0f); current.animate().alpha(1f).setDuration(280).start();
            status.setText(title); detail.setText(subtitle); spinner.setVisibility(View.VISIBLE);
        });
    }
    private void doneCurrent() { if (current != null) { String t = current.getText().toString().replaceFirst("^●", "✓"); current.setText(t); current.setTextColor(getResources().getColor(R.color.ink_secondary)); current = null; } }
    private void checkCancelled() throws Exception { if (cancelled) throw new Exception("Scan cancelled"); }
    private void copy(File src, File dst) throws Exception {
        FileInputStream in = new FileInputStream(src);
        FileOutputStream out = new FileOutputStream(dst);
        try {
            byte[] b = new byte[16384];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        } finally {
            try { in.close(); } catch (Exception ignored) { }
            try { out.close(); } catch (Exception ignored) { }
        }
    }
    private boolean deleteRecursive(File f) { if (f == null || !f.exists()) return true; if (f.isDirectory()) { File[] cs = f.listFiles(); if (cs != null) for (File c : cs) deleteRecursive(c); } return f.delete(); }
    private int dp(int v) { return (int)(v * getResources().getDisplayMetrics().density + .5f); }
}
