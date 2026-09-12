# Sentinel v1.3.7 — stability and hardening release

This release is the result of a full code-review pass over the scanner: 6 bugs fixed, dead code removed, and the build/publish pipeline made reproducible through CI. Scan logic, prompts and verdicts are unchanged.

## Fixes

- **Chat stop button works now.** Tapping the send/stop control while an AI answer was streaming set and immediately cleared the cancel flag, so chunks kept appending and the "stopped" state was overwritten by "response complete". The flag is now cleared only when a new question starts.
- **Split APKs are no longer misread as the base package.** In `.apks`/`.xapk` containers every split carries a manifest, and whichever appeared first was picked as the base — scanning resources instead of code. Base detection now requires an actual `classes.dex`.
- **No more crash on error responses without a body.** Some HTTP 4xx/5xx responses have a null error stream; the network layer now degrades to an empty body instead of throwing a NullPointerException mid-scan.
- **Large copied packages are cleaned up.** The temporary `pkg.bin` copy of a scanned package (which can be hundreds of MB) was never removed by the cache cleaner; it is now covered.
- **Safer memory use on huge games.** DEX bytes held in RAM during an APK scan are capped at 64 MB cumulative, so multi-hundred-MB game packages no longer risk an OutOfMemoryError on low-RAM phones.
- **Stale API-key ciphertext self-heals.** After a restore onto a new device the old undecryptable Keystore blob is removed automatically instead of lingering forever.

## Housekeeping

- Streams are closed on exception paths in the package-copy code paths; unused code removed from `GeminiClient`, `WebAnalyzer` and `ChatActivity`.
- New `android-ci.yml` builds the APK and runs lint on every push/PR; new `release.yml` publishes tagged releases (like this one) straight from CI.
- `SECURITY.md` documents the disclosure policy and the scanner's security design; `ANALYSIS.md` contains the full review report.

## Distribution

The APK attached to this GitHub Release is built by CI from the tagged commit — the website download buttons now point here instead of a mutable branch URL. This is a debug APK for testing; production distribution should use a separately managed signing key.
