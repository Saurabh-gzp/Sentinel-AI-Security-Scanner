# Sentinel v1.3.6 — evidence-first UX

This release replaces the installed-app blocking dialog with a full-page scan timeline. The timeline uses real scanner callbacks for package copy, package opening, DEX analysis, AI investigation and report finalization; each completed step fades in as the backend reaches it, and the fake percentage bar has been removed.

Reports now include **Ask Sentinel**, an evidence-grounded chat screen for both APK and website scans. Chat responses use Gemini SSE streaming, render progressively, support copy actions, show a stop control while the model is working, and normalize accidental JSON-wrapper responses into natural language. User and Sentinel messages use compact rounded bubbles with separate alignment and safe-area handling.

The release retains Android Keystore-backed AES-GCM API-key storage, restrictive cleartext network policy, private/loopback/link-local target blocking, invalid WebView certificate cancellation, and the documented static-analysis limitations. This is a debug APK for testing; production distribution should use a separately managed signing key and a GitHub Release asset.
