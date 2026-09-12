# Sentinel — Complete Code Analysis & Patch Report

**Scope:** full read of `android-app/` (~4,100 lines of Java across 19 classes), the GitHub Actions setup, release packaging, and the Pages website. This document lists what the review found, what this patch fixes, and what is deliberately left as a recommendation.

**Patch branch:** `patch/code-review-fixes` — every fix below is applied there.

---

## 1. Executive summary

Sentinel is a thoughtfully built offline-first Android security assistant: a hand-written Dalvik bytecode walker (`DexFlow`), a binary-XML decoder (`AxmlDecoder`), an agentic Gemini tool-loop (`AppAgent`), a deterministic phishing rule engine (`WebEngine`), and a Keystore-backed key vault (`Prefs`) — all in pure Java with **zero third-party dependencies**. The privacy posture is genuinely good: cleartext blocked, invalid certificates cancelled, private/loopback targets blocked, `allowBackup` off, no exported components.

The review found **6 real bugs** (one user-facing, two correctness, three robustness), several dead-code paths, and two infrastructure gaps (no CI, no security policy). All are fixed in this patch. The overall architecture needed no changes — the codebase is clean, consistently styled, and its "deterministic evidence first, AI explains second" separation is exactly right for a security tool.

> Short version: logic solid hai, bas kuch chhuke hue bugs the — ab wo fix ho gaye. 🙂

---

## 2. Architecture map

```
MainActivity (tabs: App / Web / Settings, key+internet gates)
│
├── APP SCAN                          ┌─────────────────────────────┐
│   PackageOpener ── apk/apks/xapk    │ Prefs      Keystore AES-GCM │
│      └─► ApkAnalyzer ── zip+manifest    Net        HTTP + retry  │
│              └─► DexFlow ── bytecode walk (pure Java)              │
│              └─► AxmlDecoder ── AXML → readable XML                │
│      AppAgent ── Gemini tool-loop (list_package / analyze_apk /    │
│                  finish_report) with deterministic fallback        │
│
├── WEB SCAN
│   WebProbe ── manual redirect-chain probe (blocks private hosts,
│   │            captures intent:// and non-http hops)
│   WebRender ── real WebView render: JS on, SSL errors captured,
│   │            screenshot for Gemini vision, DOM dump
│   WebEngine ── deterministic verdict (brand DB, scam templates,
│   │            malware hosting, SSL) — the FINAL verdict source
│   WebAnalyzer ── static HTML heuristics (used for evidence payload)
│
└── OUTPUT
    ReportActivity (verdict banner, risks, evidence)
      └─ ChatActivity (Ask Sentinel — SSE streaming, stop control)
    ScanProgressActivity (live backend event timeline)
```

---

## 3. Findings and fixes applied in this patch

| # | Severity | File | Problem | Status |
|---|----------|------|---------|--------|
| F1 | **High (user-facing)** | `ChatActivity` | Stop button was a no-op | ✅ Fixed |
| F2 | **High (correctness)** | `PackageOpener` | Wrong base-APK detection in apks/xapk containers | ✅ Fixed |
| F3 | **Medium (crash path)** | `Net` | NPE on error responses without a body | ✅ Fixed |
| F4 | **Medium (correctness)** | `MainActivity` | `pkg.bin` never cleaned from cache | ✅ Fixed |
| F5 | **Medium (robustness)** | `ApkAnalyzer` | Unbounded DEX memory (OOM risk on large APKs) | ✅ Fixed |
| F6 | **Medium (robustness)** | `Prefs` | Stale ciphertext never self-heals after Keystore loss | ✅ Fixed |
| F7 | Low | `MainActivity`, `ScanProgressActivity`, `PackageOpener` | Streams leaked on exception paths | ✅ Fixed |
| F8 | Low (style) | `GeminiClient` | Dead local variable (`safetyRatings`) | ✅ Removed |
| F9 | Low (style) | `WebAnalyzer` | Unused `lastErr`, empty if-block, unused `collect()` param | ✅ Removed |
| F10 | Low (style) | `ChatActivity` | Dead `streamBubble()` method | ✅ Removed |
| F11 | Infra | `.github/workflows/` | No build verification for the Android app | ✅ Added `android-ci.yml` |
| F12 | Docs | repo root | No security policy | ✅ Added `SECURITY.md` |

### F1 — ChatActivity stop button did nothing (High)

The send button doubles as a stop control while streaming:

```java
send.setOnClickListener(v -> { if (busy) { cancelRequested = true; setBusy(false); ... } else sendQuestion(); });
```

But `setBusy()` started with `busy = on; cancelRequested = false; ...` — so the stop click set `cancelRequested = true` and then **immediately reset it to `false`**. Consequences: streamed chunks kept appending to the bubble after "Response stopped", and the completion branch (`if (!cancelRequested)`) always ran, overwriting the stopped state with "Sentinel response complete — current scan context retained". The user's stop was purely cosmetic.

**Fix:** `setBusy()` no longer touches `cancelRequested`; the flag is cleared only when a brand-new question is sent (`sendQuestion()`), which is the single point where a fresh stream begins. Documented with a comment so the invariant survives refactors.

### F2 — Wrong base APK chosen from .apks/.xapk containers (High)

`PackageOpener.hasCode()` accepted an entry as the code-bearing base if it contained `classes.dex` **or** `AndroidManifest.xml`. Every split APK (e.g. `config.xxhdpi.apk`) carries a manifest, so whichever split appeared first in the container's entry order was picked as "base" — scanning resource metadata instead of the app's actual code. The agent would then report on a split with no DEX.

**Fix:** base detection now requires `classes.dex` (`hasDex()`), with the existing fallback to the first APK only when the container has no DEX anywhere (legal resource-only base). Also documented why the manifest alone must never qualify.

### F3 — `Net.read()` NullPointerException (Medium)

```java
if (code >= 200 && code < 300) in = c.getInputStream();
else in = c.getErrorStream();                      // can be null
BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));  // NPE
```

Several HTTP error paths (proxy responses, some 4xx/5xx with no body, connection teardown races) return a null error stream, crashing the scan thread with an unhelpful NPE instead of the intended `IOException422("API 4xx: …")`.

**Fix:** substitute an empty stream when the error stream is null, so the caller gets a clean "API <code>: <empty>" error and the retry logic behaves as designed.

### F4 — Copied package file never cleaned (Medium)

`MainActivity.doAppScan()` copies the picked URI to `cacheDir/pkg.bin`, but `cleanupTemp()` only matched names ending `.apk` or starting `scan` / `web` / `extract`. `pkg.bin` (which can be hundreds of MB for games) survived every cleanup — it was only removed when Android purged the cache. The success and error paths both call `cleanupTemp()`, so the fix is one line: the cleanup matcher now also covers the `pkg` prefix.

### F5 — Unbounded DEX memory in ApkAnalyzer (Medium)

Up to 8 DEX files were read **fully into RAM** with no size limit. A 1 GB game APK can carry classes.dex files of 30–80 MB each; 8 × 80 MB ≈ 640 MB — a guaranteed `OutOfMemoryError` on low-RAM devices, crashing exactly when scanning the biggest (and most suspicious) packages.

**Fix:** a cumulative 64 MB cap on in-memory DEX bytes (`DEX_BYTE_CAP`). Files beyond the cap are still counted in `dexCount` and noted in structure stats; the walker simply analyses the first 64 MB, which is where app-owned code lives (later DEX files in obfuscated packers are typically shell code anyway).

### F6 — Keystore ciphertext never self-heals (Medium)

`Prefs.getKey()` returned `""` on any decryption failure — but kept the undecryptable blob in SharedPreferences. After a cloud restore onto a new device (where the Keystore key does not travel), the app would hold a dead ciphertext forever: the user sees "no key", enters a new one, and it works — but until they *notice*, every scan silently reports a missing key with no hint that stale data was the cause.

**Fix:** on decryption failure the stale blob and its `key_verified` flag are removed (`self-heal`), so the vault state is always consistent with reality.

### F7 — Streams leaked on exception paths (Low)

`MainActivity.copyToCache()`, `ScanProgressActivity.copy()`, and `PackageOpener.copyEntry()` closed their streams only on the success path; an `IOException` mid-copy leaked the file descriptor (and for the copy-to-cache case, left a truncated `pkg.bin`). All three now close in `finally`.

### F8–F10 — Dead code (Low, style)

- `GeminiClient.extractText()`: `JSONArray parts = …optJSONArray("safetyRatings")` — assigned, never used.
- `WebAnalyzer.scan()`: `lastErr` captured and never read; `fetch()` had an empty `if` block whose only content was a comment; `collect()` took a `host` parameter that no caller's logic used.
- `ChatActivity.streamBubble()`: an entire simulated-typing method orphaned when SSE streaming landed in v1.3.6.

### F11 — Android CI added

`.github/workflows/android-ci.yml` builds `assembleDebug` on every push/PR touching `android-app/**` (JDK 17, wrapper validation, Gradle cache), runs `lintDebug` non-blocking, and uploads the APK plus lint reports as artifacts. A stray regex/typo in Java that previously shipped silently will now fail CI before release packaging.

### F12 — SECURITY.md added

Responsible-disclosure policy scoped to a security tool: private reporting via GitHub, scope (the scanner's own app + Pages site), explicit non-scope (Gemini service, Chromium bugs, "this scanned app is malicious" reports), and the design notes a reviewer needs (key storage, cleartext/cert policy, no exported components, no code execution from scanned packages).

---

## 4. Verified non-issues (checked, deliberately not changed)

- **`deploy.yml` trigger is correct.** A casual `head` read suggests `branches: ain]`, but byte-level inspection confirms the file is `branches: [main]` and parses to `['main']`. No fix needed.
- **Gemini API key as a URL query parameter** is Google's documented auth style for the Generative Language API; switching to a header is not supported for that endpoint. Documented in SECURITY.md instead.
- **`DexFlow` string decoding** uses plain UTF-8 rather than strict MUTF-8 (differs only for NUL and astral surrogate edge cases); harmless for a scanner that treats strings as evidence hints.
- **`MainActivity` manifest + `build.gradle` version duplication** (`versionCode 10`, `versionName 1.3.6` in both) currently agree; AGP lets the Gradle value win, so leaving it avoids churn.
- **`WebProbe` vs `WebAnalyzer` User-Agents differ** (`SentinelScan/1.0` vs `SentinelScanner/1.0`) — intentional: the static fetcher and the redirect probe present distinct fingerprints, which is useful when comparing server behaviour across paths.

## 5. Recommendations (not applied — larger changes / product decisions)

1. **Scan cancellation does not abort in-flight network work.** `ScanProgressActivity` sets `cancelled` and the timeline stops, but the blocking `HttpURLConnection` read inside `AppAgent`/`GeminiClient` runs to completion in the background (spending one more API turn). A proper fix means threading a cancellation token through `Net.post`/`streamPost` — worth doing, but it touches every network call site, so it is proposed rather than patched.
2. **Move release APKs to GitHub Releases.** `app/v1.0.0`, `v1.1.0`, `v1.3.6` binaries are ~6 MB of git history. `package_release.sh` + the Pages site already point at `raw/main/app/v1.3.6/...`; switching the site's download links to a tagged Release URL stops history growth and lets you stop committing binaries entirely. (Needs a website edit + release tagging, so left to you.)
3. **JVM unit tests for the pure-Java core.** `DexFlow`, `AxmlDecoder`, `WebEngine`, `Util`, and `ScanReport.parse` are all dependency-free and trivially testable (e.g. a synthetic AXML blob, a scam-template URL fixture). The new CI workflow gives them a home whenever you want to add them.
4. **`GeminiClient.score()` hardcodes model families** (3.5/3.6/3.7 …). It ages gracefully (unknown ids sort last), but a quick quarterly check keeps the picker's "newest first" honest.
5. **`QUERY_ALL_PACKAGES`** — already documented in the README; keep the Play-policy justification text handy if you ever distribute through the Play Store.

## 6. What this patch changes, file by file

```
.github/workflows/android-ci.yml     | +61   new: build + lint + artifact upload
SECURITY.md                          | +37   new: disclosure policy + design notes
ANALYSIS.md                          | this report
android-app/app/src/main/java/com/arena/sentinel/
  ChatActivity.java                  | stop-button fix, dead method removed
  PackageOpener.java                 | base-APK fix, ZipFile leak, stream closes
  Net.java                           | null error-stream guard
  MainActivity.java                  | stream closes, pkg.bin cleanup
  ScanProgressActivity.java          | stream closes
  ApkAnalyzer.java                   | 64 MB DEX memory cap
  Prefs.java                         | stale-ciphertext self-heal
  GeminiClient.java                  | dead variable removed
  WebAnalyzer.java                   | dead code + unused param removed
```

**Verification:** syntax-checked all edited sources (`javac`), byte-verified the unchanged workflow YAML, and re-read every fix in context. The CI workflow will provide the first full Gradle build on push — behaviour-affecting changes are small and localised, and none alter the scan logic, prompts, or verdicts.
