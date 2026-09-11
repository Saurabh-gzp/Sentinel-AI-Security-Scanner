package com.arena.sentinel;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Evidence-grounded chat with streamed rendering, loading state and copy actions. */
public class ChatActivity extends Activity {
    private LinearLayout messages;
    private EditText input;
    private TextView send;
    private TextView status;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean busy = false;
    private boolean cancelRequested = false;
    private Runnable dotsTask;
    private static final StringBuilder HISTORY = new StringBuilder();
    private static String HISTORY_TARGET = "";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        setContentView(R.layout.activity_chat);
        messages = findViewById(R.id.chatMessages); input = findViewById(R.id.chatInput);
        send = findViewById(R.id.chatSend); status = findViewById(R.id.chatStatus);
        View root = findViewById(android.R.id.content);
        View composer = findViewById(R.id.chatComposer);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            int ime = android.os.Build.VERSION.SDK_INT >= 30 ? insets.getInsets(android.view.WindowInsets.Type.ime()).bottom : insets.getSystemWindowInsetBottom();
            composer.setTranslationY(-ime);
            if (ime > 0) ((ScrollView) findViewById(R.id.chatScroll)).post(() -> ((ScrollView) findViewById(R.id.chatScroll)).fullScroll(View.FOCUS_DOWN));
            return insets;
        });
        root.requestApplyInsets();
        input.setOnFocusChangeListener((v, hasFocus) -> { if (hasFocus) input.postDelayed(() -> ((ScrollView) findViewById(R.id.chatScroll)).fullScroll(View.FOCUS_DOWN), 180); });
        View top = findViewById(R.id.chatTopBar);
        top.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(dp(12), insets.getSystemWindowInsetTop() + dp(4), dp(12), dp(8)); return insets;
        }); top.requestApplyInsets();
        findViewById(R.id.chatBack).setOnClickListener(v -> finish());
        send.setOnClickListener(v -> { if (busy) { cancelRequested = true; setBusy(false); status.setText("Response stopped"); } else sendQuestion(); });
        if (ReportActivity.LAST != null) {
            String target = ReportActivity.LAST.target == null ? "" : ReportActivity.LAST.target;
            if (!target.equals(HISTORY_TARGET)) { HISTORY.setLength(0); HISTORY_TARGET = target; }
            addBubble("Sentinel", "Main current scan ke captured evidence ko remember karke isi context mein jawab dunga. Naya scan tabhi hoga jab aap explicitly kahenge.", false, true);
        }
    }

    private void sendQuestion() {
        String question = input.getText().toString().trim();
        if (question.isEmpty() || ReportActivity.LAST == null) return;
        input.setText(""); addBubble("You", question, true, true); addAction("Using current scan context — no rescan requested"); setBusy(true);
        final TextView liveText = createLiveBubble();
        final StringBuilder liveAnswer = new StringBuilder();
        final ScanReport report = ReportActivity.LAST;
        new Thread(() -> {
            try {
                runOnUiThread(() -> addAction("Preparing captured evidence for this question"));
                String evidence = Util.clip(report.evidence == null ? "" : report.evidence, 12000);
                String previous = Util.clip(HISTORY.toString(), 5000);
                String prompt = "You are Sentinel, a careful Android and web security analyst. Answer the user's question using ONLY the scan evidence below. "
                        + "Never output JSON, XML, markdown wrapper fields such as response, or labels like Sentinel:; return only the natural-language answer. "
                        + "If evidence does not prove something, say that clearly; never invent files, APIs, or behavior. Explain APK manifest, permissions, exported components, DEX call-sites, URLs, native libraries and workflow when present. "
                        + "For websites explain URL, redirects, SSL, forms, scripts, iframes and phishing signals when present. Answer in polite Hinglish (Roman Hindi with technical terms). Do not rescan, unpack, search files, or run tools unless the user explicitly requests a new scan.\n\n"
                        + "SCAN TYPE: " + report.type + "\nTARGET: " + report.target + "\nVERDICT: " + verdict(report.verdict)
                        + "\nSUMMARY: " + report.summary + "\nEVIDENCE:\n" + evidence + "\n\nPREVIOUS CHAT:\n" + previous + "\n\nUSER QUESTION: " + question;
                runOnUiThread(() -> addAction("Sending question to Sentinel AI stream"));
                GeminiClient.streamGenerate(Prefs.getKey(this), Prefs.getModel(this), prompt, chunk -> {
                    if (cancelRequested) return;
                    liveAnswer.append(chunk);
                    runOnUiThread(() -> { liveText.setText("Sentinel\n" + cleanAnswer(liveAnswer.toString())); scrollDown(); });
                });
                if (!cancelRequested) runOnUiThread(() -> { String answer = cleanAnswer(liveAnswer.toString()); HISTORY.append("User: ").append(question).append("\nSentinel: ").append(answer).append("\n"); setBusy(false); liveText.setText("Sentinel\n" + answer); addAction("Sentinel response complete — current scan context retained"); });
            } catch (Exception e) {
                if (cancelRequested) return;
                runOnUiThread(() -> { setBusy(false); liveText.setText("Sentinel\nIs question ka jawab abhi nahi mil paaya. Please dobara try karein."); });
            }
        }).start();
    }

    private void streamBubble(String answer) {
        setBusy(false);
        LinearLayout row = createRow(false);
        LinearLayout bubble = createBubble(false);
        TextView text = messageText("Sentinel\n", false);
        TextView copy = copyButton(text);
        bubble.addView(text); bubble.addView(copy); row.addView(bubble); messages.addView(row);
        final int[] at = {0};
        Runnable stream = new Runnable() { public void run() {
            if (at[0] >= answer.length()) { status.setText("Evidence-grounded chat"); return; }
            int next = Math.min(answer.length(), at[0] + 4);
            text.setText("Sentinel\n" + answer.substring(0, next)); at[0] = next; scrollDown(); handler.postDelayed(this, 18);
        }};
        handler.post(stream);
    }

    private TextView createLiveBubble() {
        LinearLayout row = createRow(false); LinearLayout bubble = createBubble(false);
        TextView text = messageText("Sentinel\n", false); bubble.addView(text); bubble.addView(copyButton(text)); row.addView(bubble); messages.addView(row); scrollDown(); return text;
    }

    private void addBubble(String who, String body, boolean user, boolean withCopy) {
        LinearLayout row = createRow(user);
        LinearLayout bubble = createBubble(user);
        TextView text = messageText(who + "\n" + body, user);
        bubble.addView(text); if (withCopy) bubble.addView(copyButton(text));
        row.addView(bubble); messages.addView(row); scrollDown();
    }

    private void addAction(String action) {
        TextView t = new TextView(this); t.setText("⌁  " + action); t.setTextSize(12); t.setTextColor(getResources().getColor(R.color.ink_faint)); t.setPadding(dp(8), dp(9), dp(8), dp(2));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.topMargin = dp(4); messages.addView(t, lp); scrollDown();
    }

    private LinearLayout createRow(boolean user) {
        LinearLayout row = new LinearLayout(this); row.setOrientation(LinearLayout.HORIZONTAL); row.setGravity(user ? Gravity.END : Gravity.START);
        row.setLayoutParams(new LinearLayout.LayoutParams(-1, -2)); return row;
    }
    private LinearLayout createBubble(boolean user) {
        LinearLayout bubble = new LinearLayout(this); bubble.setOrientation(LinearLayout.VERTICAL); bubble.setPadding(dp(15), dp(11), dp(10), dp(8));
        GradientDrawable bg = new GradientDrawable(); bg.setColor(getResources().getColor(user ? R.color.coral : R.color.surface_alt)); bg.setCornerRadius(dp(18));
        bubble.setBackground(bg); LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams((int)(getResources().getDisplayMetrics().widthPixels * .82f), -2); lp.topMargin = dp(10); bubble.setLayoutParams(lp); return bubble;
    }
    private TextView messageText(String value, boolean user) { TextView t = new TextView(this); t.setText(value); t.setTextSize(15); t.setLineSpacing(0, 1.12f); t.setTextColor(getResources().getColor(user ? R.color.surface : R.color.ink)); return t; }
    private TextView copyButton(TextView source) {
        TextView c = new TextView(this); c.setText("⧉  Copy"); c.setTextSize(12); c.setTextColor(getResources().getColor(R.color.ink_secondary)); c.setGravity(Gravity.END); c.setPadding(0, dp(8), dp(2), 0);
        c.setOnClickListener(v -> { String value = source.getText().toString(); int nl = value.indexOf('\n'); if (nl >= 0) value = value.substring(nl + 1); ((ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Sentinel message", value)); c.setText("✓  Copied"); handler.postDelayed(() -> c.setText("⧉  Copy"), 1500); }); return c;
    }
    private void setBusy(boolean on) { busy = on; cancelRequested = false; send.setText(on ? "■" : "SEND"); status.setText(on ? "Sentinel is thinking" : "Evidence-grounded chat"); if (on) animateDots(); else if (dotsTask != null) handler.removeCallbacks(dotsTask); }
    private void animateDots() { final int[] n={0}; dotsTask = new Runnable(){ public void run(){ if(!busy)return; n[0]=(n[0]+1)%4; String d=""; for(int i=0;i<n[0];i++)d+="."; status.setText("Sentinel is thinking"+d); handler.postDelayed(this,350); }}; handler.post(dotsTask); }
    private void scrollDown() { ((ScrollView)findViewById(R.id.chatScroll)).post(() -> ((ScrollView)findViewById(R.id.chatScroll)).fullScroll(View.FOCUS_DOWN)); }
    private String cleanAnswer(String raw) { String s = raw == null ? "" : raw.trim(); if (s.startsWith("{") && s.contains("\"response\"")) { int i=s.indexOf("\"response\""); int colon=s.indexOf(':',i); if(colon>=0)s=s.substring(colon+1).trim(); if(s.startsWith("\""))s=s.substring(1); if(s.endsWith("}"))s=s.substring(0,s.length()-1); s=s.replace("\\n","\n").replace("\\\"","\""); } if(s.startsWith("Sentinel:"))s=s.substring(9).trim(); return s; }
    private String verdict(int v) { return v == ScanReport.SAFE ? "Safe" : v == ScanReport.MALICIOUS ? "Malicious" : "Suspicious"; }
    private int dp(int v) { return (int)(v * getResources().getDisplayMetrics().density + .5f); }
}
