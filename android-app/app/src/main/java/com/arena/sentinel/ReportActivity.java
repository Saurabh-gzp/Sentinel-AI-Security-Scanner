package com.arena.sentinel;

import android.app.Activity;
import android.graphics.PorterDuff;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ReportActivity extends Activity {

    static ScanReport LAST;

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        setContentView(R.layout.activity_report);

        // edge-to-edge: inset top bar below status bar
        View root = findViewById(R.id.reportRoot);
        final View topbar = findViewById(R.id.reportTopBar);
        root.setOnApplyWindowInsetsListener((v, ins) -> {
            topbar.setPadding(dp(20), ins.getSystemWindowInsetTop() + dp(4), dp(20), dp(10));
            return ins;
        });
        root.requestApplyInsets();

        findViewById(R.id.backBtn).setOnClickListener(v -> finish());
        findViewById(R.id.chatBtn).setOnClickListener(v -> startActivity(new android.content.Intent(this, ChatActivity.class)));

        if (LAST == null) { finish(); return; }
        ScanReport rep = LAST;

        ((TextView) findViewById(R.id.reportTitle)).setText(rep.type);

        // verdict banner
        View banner = findViewById(R.id.verdictBanner);
        FrameLayout iconWrap = findViewById(R.id.verdictIconWrap);
        ImageView icon = findViewById(R.id.verdictIcon);
        TextView label = findViewById(R.id.verdictLabel);
        TextView conf = findViewById(R.id.verdictConfidence);

        int v = rep.verdict;
        int fg, soft, iconSrc;
        String labelText;
        if (v == ScanReport.SAFE) {
            fg = R.color.safe; soft = R.color.safe_soft; iconSrc = R.drawable.ic_check; labelText = "SAFE";
        } else if (v == ScanReport.SUSPICIOUS) {
            fg = R.color.warn; soft = R.color.warn_soft; iconSrc = R.drawable.ic_alert; labelText = "SUSPICIOUS";
        } else {
            fg = R.color.danger; soft = R.color.danger_soft; iconSrc = R.drawable.ic_alert; labelText = "MALICIOUS";
        }
        banner.getBackground().setColorFilter(getResources().getColor(soft), PorterDuff.Mode.SRC_ATOP);
        iconWrap.setBackgroundColor(getResources().getColor(soft));
        icon.setImageResource(iconSrc);
        icon.setColorFilter(getResources().getColor(fg));
        label.setText(labelText);
        label.setTextColor(getResources().getColor(fg));
        conf.setText("Confidence " + rep.confidence + "%  ·  " + rep.type);

        ((TextView) findViewById(R.id.targetText)).setText(rep.target);

        // summary
        bindSection(R.id.secSummary, "Summary", rep.summary);
        // recommendation
        bindSection(R.id.secAdvice, "Recommendation",
                rep.recommendation.isEmpty() ? "No specific advice." : rep.recommendation);
        // practical advice (ToS/account-ban/privacy)
        bindSection(R.id.secPractical, "Practical advice",
                rep.practicalAdvice.isEmpty() ? "—" : rep.practicalAdvice);

        // risks
        LinearLayout risks = findViewById(R.id.risksList);
        if (rep.risks.isEmpty()) {
            TextView none = new TextView(this);
            none.setText("No significant risks found.");
            none.setTextColor(getResources().getColor(R.color.ink_faint));
            int p = dp(8);
            none.setPadding(p, dp(12), p, p);
            risks.addView(none);
        } else {
            for (ScanReport.Risk rk : rep.risks) risks.addView(buildRiskRow(rk));
        }

        // positives
        LinearLayout pos = findViewById(R.id.positivesList);
        if (rep.positives.isEmpty()) {
            TextView none = new TextView(this);
            none.setText("None noted.");
            none.setTextColor(getResources().getColor(R.color.ink_faint));
            int p = dp(8);
            none.setPadding(p, dp(12), p, p);
            pos.addView(none);
        } else {
            for (String pp : rep.positives) pos.addView(buildBullet(pp));
        }

        ((TextView) findViewById(R.id.evidenceText)).setText(rep.evidence);
    }

    private void bindSection(int id, String title, String body) {
        View sec = findViewById(id);
        ((TextView) sec.findViewById(R.id.sectionTitle)).setText(title);
        ((TextView) sec.findViewById(R.id.sectionBody)).setText(body);
    }

    private View buildRiskRow(ScanReport.Risk rk) {
        View row = LayoutInflater.from(this).inflate(R.layout.item_risk, null);
        View dot = row.findViewById(R.id.sevDot);
        TextView chip = row.findViewById(R.id.sevChip);
        ((TextView) row.findViewById(R.id.riskTitle)).setText(rk.title);
        ((TextView) row.findViewById(R.id.riskDetail)).setText(rk.detail);

        int fg, soft;
        String sev = rk.severity;
        if ("High".equals(sev)) { fg = R.color.danger; soft = R.color.danger_soft; }
        else if ("Low".equals(sev)) { fg = R.color.info; soft = R.color.info_soft; }
        else { fg = R.color.warn; soft = R.color.warn_soft; }

        dot.getBackground().setColorFilter(getResources().getColor(fg), PorterDuff.Mode.SRC_ATOP);
        chip.setText(sev);
        chip.setTextColor(getResources().getColor(fg));
        chip.setBackgroundColor(getResources().getColor(soft));
        return row;
    }

    private View buildBullet(String text) {
        View b = LayoutInflater.from(this).inflate(R.layout.item_bullet, null);
        ((TextView) b.findViewById(R.id.bulletText)).setText(text);
        return b;
    }

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
}
