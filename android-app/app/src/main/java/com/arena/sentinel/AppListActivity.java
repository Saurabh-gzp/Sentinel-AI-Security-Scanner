package com.arena.sentinel;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

/** Installed-app picker. User apps are sorted newest-first by first install time. */
public class AppListActivity extends Activity {
    private AppAdapter adapter;
    private final List<AppInfo> allApps = new ArrayList<>();
    private final List<AppInfo> filtered = new ArrayList<>();
    private ProgressBar progress;
    private EditText search;

    static class AppInfo {
        String name, pkg, sourceDir, installedLabel;
        long firstInstallTime;
        Drawable icon;
    }

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        setContentView(R.layout.activity_app_list);
        View root = findViewById(R.id.appListRoot);
        final View topbar = findViewById(R.id.appListTopBar);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            topbar.setPadding(dp(20), insets.getSystemWindowInsetTop() + dp(4), dp(20), dp(10));
            return insets;
        });
        root.requestApplyInsets();
        progress = findViewById(R.id.appListProgress);
        search = findViewById(R.id.appSearch);
        findViewById(R.id.appListBack).setOnClickListener(v -> finish());
        adapter = new AppAdapter();
        ((ListView) findViewById(R.id.appListView)).setAdapter(adapter);
        ((ListView) findViewById(R.id.appListView)).setOnItemClickListener((p, v, pos, id) -> confirmScan(filtered.get(pos)));
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(Editable e) { filter(e.toString()); }
        });
        loadApps();
    }

    private void loadApps() {
        new Thread(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(0);
            allApps.clear();
            for (ApplicationInfo ai : apps) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                AppInfo info = new AppInfo();
                info.name = pm.getApplicationLabel(ai).toString();
                info.pkg = ai.packageName;
                info.sourceDir = ai.sourceDir;
                try {
                    PackageInfo pi = pm.getPackageInfo(ai.packageName, 0);
                    info.firstInstallTime = pi.firstInstallTime;
                    info.installedLabel = "Installed " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(pi.firstInstallTime));
                } catch (Exception ignored) { info.installedLabel = "Installed date unavailable"; }
                try { info.icon = pm.getApplicationIcon(ai); } catch (Exception ignored) {}
                allApps.add(info);
            }
            Collections.sort(allApps, (a, b) -> {
                int byTime = Long.compare(b.firstInstallTime, a.firstInstallTime);
                return byTime != 0 ? byTime : a.name.compareToIgnoreCase(b.name);
            });
            filtered.clear();
            filtered.addAll(allApps);
            runOnUiThread(() -> { progress.setVisibility(View.GONE); adapter.notifyDataSetChanged(); });
        }).start();
    }

    private void filter(String q) {
        filtered.clear();
        String lq = q.toLowerCase();
        for (AppInfo a : allApps)
            if (lq.isEmpty() || a.name.toLowerCase().contains(lq) || a.pkg.toLowerCase().contains(lq)) filtered.add(a);
        adapter.notifyDataSetChanged();
    }

    static boolean shouldOpenSettings = false;
    private void confirmScan(AppInfo info) {
        if (Prefs.getKey(this).isEmpty()) {
            shouldOpenSettings = true;
            new AlertDialog.Builder(this).setTitle("API key required")
                    .setMessage("Gemini API key Settings me add karein, phir installed app scan karein.")
                    .setPositiveButton("Go to Settings", (d, w) -> finish()).setCancelable(false).show();
            return;
        }
        new AlertDialog.Builder(this).setTitle("Scan \"" + info.name + "\"?")
                .setMessage(info.installedLabel + "\nPackage: " + info.pkg + "\n\nFull-page progress ke saath scan hoga.")
                .setPositiveButton("Start scan", (d, w) -> startProgress(info))
                .setNegativeButton("Cancel", null).show();
    }

    private void startProgress(AppInfo info) {
        Intent i = new Intent(this, ScanProgressActivity.class);
        i.putExtra("sourceDir", info.sourceDir); i.putExtra("appName", info.name); i.putExtra("packageName", info.pkg);
        startActivity(i); finish();
    }

    class AppAdapter extends BaseAdapter {
        public int getCount() { return filtered.size(); }
        public Object getItem(int p) { return filtered.get(p); }
        public long getItemId(int p) { return p; }
        public View getView(int p, View conv, ViewGroup parent) {
            if (conv == null) conv = LayoutInflater.from(AppListActivity.this).inflate(R.layout.item_app_list, parent, false);
            AppInfo info = filtered.get(p);
            ImageView icon = conv.findViewById(R.id.itemIcon);
            if (info.icon != null) icon.setImageDrawable(info.icon); else icon.setImageResource(android.R.drawable.sym_def_app_icon);
            ((TextView) conv.findViewById(R.id.itemName)).setText(info.name);
            ((TextView) conv.findViewById(R.id.itemPkg)).setText(info.pkg + "  ·  " + info.installedLabel);
            return conv;
        }
    }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
}
