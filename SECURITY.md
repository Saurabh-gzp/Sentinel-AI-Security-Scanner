# Security Policy

Sentinel is itself a security tool, so reports about its own behaviour are taken seriously. Thank you for looking closely.

## Supported versions

Only the latest tagged release (currently **v1.3.6**, `versionCode 10`) receives security fixes. The debug APKs published under `app/v*` in this repository are for testing; if you package Sentinel for distribution, build from `android-app/` and apply your own signing key.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

1. Use GitHub's **Private vulnerability reporting** (Repository → Security → Report a vulnerability), or
2. Contact the maintainer via the GitHub profile: [Saurabh-gzp](https://github.com/Saurabh-gzp).

Include: affected version/commit, a description, reproduction steps, and — if possible — evidence such as a stack trace or screenshot. You will get an acknowledgement within 7 days and a status update at least every 14 days until the issue is resolved.

## Scope

In scope:

- The scanner's own Android app (`android-app/`): the WebView render sandbox, private/loopback target blocking, API-key storage (`Prefs`, Android Keystore AES-GCM), network handling (`Net`, `WebProbe`, `WebRender`), package parsing (`ApkAnalyzer`, `DexFlow`, `AxmlDecoder`, `PackageOpener`), and IPC/exported-component surface (`AndroidManifest.xml`).
- The GitHub Pages website (`web/`) — e.g. script injection or download-link tampering.

Out of scope:

- The Gemini API service itself (report to Google).
- Bugs in third-party WebView/Chromium (report to the Chromium project).
- Reports that a *scanned* app is malicious — that is Sentinel's normal output, not a Sentinel vulnerability.
- Static-analysis false negatives/positives are quality issues, not security vulnerabilities; please file a normal issue with the evidence.

## Design notes relevant to security review

- The Gemini API key is entered by the user, encrypted with an Android Keystore AES-GCM key, and never bundled into the APK or logged. It is sent only to `generativelanguage.googleapis.com` as a query parameter (Google's documented auth style).
- The app blocks cleartext traffic (`usesCleartextTraffic="false"`, plus `network_security_config`), refuses invalid WebView certificates, and blocks loopback / private / link-local / multicast scan targets to prevent SSRF-style abuse of the scanner.
- All non-launcher activities are `exported="false"`; there are no services, receivers, or content providers.
- Sentinel never executes code from scanned packages; DEX files are parsed as data (`DexFlow` is a read-only bytecode walker).
- `QUERY_ALL_PACKAGES` is used only to list user-installed apps in the picker; see the README note on Play policy.

## Known limitations (not vulnerabilities)

Static analysis cannot see reflection, encrypted or dynamically downloaded payloads, native-library behaviour, or server-side decisions. A `Safe` verdict means "no strong red flags in the collected evidence", not "guaranteed harmless". The in-app scanner event timeline intentionally never fakes progress; cancelled scans may still finish their network calls in the background because the streaming HTTP read cannot be interrupted mid-flight (see `ANALYSIS.md`).
