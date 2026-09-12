# Sentinel — AI Security Scanner

Sentinel is an Android security assistant for inspecting APK/APKS/XAPK packages and checking suspicious website links. It combines deterministic evidence collection with an optional Gemini report written in Hinglish.

> **Important:** Sentinel is an assistant, not an antivirus or a guarantee of safety. A `Safe` result means that no strong red flags were found in the collected evidence; it does not prove that an app or website is harmless. Treat `Suspicious` and `Unknown` cases conservatively.

## What it checks

- Android package structure, manifest permissions, exported components, DEX call-sites, URLs/IP literals, native libraries and selected sensitive API workflows.
- Website redirects, HTTPS/certificate state, credential forms, brand impersonation patterns, non-HTTP redirects, suspicious download patterns and rendered-page signals.
- Optional Gemini analysis. The deterministic rule engine remains the source of the web verdict; Gemini explains the evidence.

## Privacy and security

APK metadata, extracted code excerpts and (for web scans) an optional screenshot may be sent to Gemini when you enable AI analysis. Do not scan confidential packages or private links unless you understand this data flow. The Gemini API key is entered by the user and stored using Android Keystore-backed AES-GCM encryption; it is never bundled in the APK.

The scanner blocks cleartext app traffic, invalid WebView certificates, and loopback/private/link-local/multicast targets to reduce local-network and SSRF-style abuse. It does not execute APK code.

## Build from source

The reproducible Android project is in [`android-app/`](android-app/). Open that directory in Android Studio or run:

```bash
cd android-app
./gradlew assembleDebug
```

The build requires Android SDK 35 and Android Gradle Plugin 8.6.1. The generated debug APK is `android-app/app/build/outputs/apk/debug/app-debug.apk`. For production distribution, use a private signing key and publish through a tagged GitHub Release rather than a mutable branch URL.

## v1.3 user experience

Installed apps are sorted by first-install time, newest first, with the install date shown in each row. Selecting an installed app opens a full-page progress timeline rather than a blocking dialog. Reports now include an **Ask Sentinel** chat action. The chat answers follow-up questions from the captured scan evidence and is deliberately instructed not to invent missing files or runtime behavior.

## Limitations

Static analysis can miss reflection, encrypted or dynamically downloaded code, native-library behavior, runtime-only payloads and server-side decisions. Heuristics can also produce false positives for legitimate security research, developer tools and unusual domains. Keep the evidence visible in reports and do not rely on a single confidence number.

`QUERY_ALL_PACKAGES` is used only for the installed-app picker. If distributing through Google Play, review the current Play policy and provide the required core-functionality justification.

## License

MIT.

## v1.3.1 interaction updates

The installed-app scanner now exposes backend-driven progress rather than a simulated percentage. Package copying, package opening, DEX analysis, agent investigation and report finalization are shown as separate events, with each completed step animated into view. Reports include Ask Sentinel, which uses Gemini server-sent events for progressive answers, normalizes accidental JSON wrappers, and provides copy controls for both user questions and assistant replies.

## v1.3.2 progress correctness

The scan progress view is now a dynamic backend event log. It does not pre-render a fixed checklist or simulate completion percentages. Rows are added only when package copy, package opening, manifest/DEX/native structure parsing, agent turns, decompilation callbacks, report preparation, or cleanup actually run.

## v1.3.3 key setup guard

A scan cannot start without a Gemini API key. All scan entry points enforce this guard, return the user to Settings, and provide a direct “How to create a Gemini API key” tutorial button linked to the supplied YouTube guide.

## v1.3.4 chat context and alignment

User bubbles are right-aligned and Sentinel bubbles are left-aligned. The current report evidence and recent conversation are retained as the active chat context, while prompts explicitly prevent rescanning or backend tool work unless the user requests it. Visible action rows show context loading, evidence preparation, AI stream start, and response completion.

## v1.3.5 keyboard-aware chat composer

The chat composer now observes IME window insets and translates itself above the keyboard while typing. It returns to the normal bottom position when the keyboard closes, and the transcript scrolls to keep the active composer context visible.

## v1.3.6 streaming latency

The chat stream remains genuine Gemini SSE (chunks are rendered as they arrive, not replayed after a complete response). The request now caps output at 700 tokens to reduce time-to-complete and keeps the current scan evidence/context without triggering a rescan.

## v1.3.7 stability and hardening

A full code-review pass fixed six bugs (chat stop button was a no-op, split APKs misdetected as the base package, NPE on body-less error responses, `pkg.bin` cache leak, unbounded DEX memory, stale Keystore ciphertext) and removed dead code without touching scan logic or verdicts. Releases are now built by CI: tagging `v*` publishes the APK, source zip and SHA256SUMS as a GitHub Release, and the website download buttons point at the tagged release instead of a mutable branch URL. See [`ANALYSIS.md`](ANALYSIS.md) for the complete review and [`RELEASE_NOTES_v1.3.7.md`](RELEASE_NOTES_v1.3.7.md) for the changelog.

