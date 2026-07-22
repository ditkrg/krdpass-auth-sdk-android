# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1]

### Fixed

- Restore Expo SDK 55 consumer compatibility by publishing Kotlin 2.2 metadata
  and using kotlinx-serialization 1.9, the newest release whose metadata its
  Kotlin 2.1 compiler can read.

### Changed

- Update OkHttp 5.1 -> 5.4 and the AndroidX testing libraries without changing
  the public API.

## [1.1.0]

### Changed

- Toolchain currency: Kotlin 2.2.20 -> 2.4.0 and kotlinx-serialization 1.9.0 -> 1.10.0.
  No public API or behavior change (guarded by the API-compatibility baseline).

### Added

- Static analysis: detekt with a project config and baseline.
- Public API baseline (`library/api/library.api`) checked in CI to guard the
  cross-SDK API surface against accidental drift.

## [1.0.1]

### Security

- Enforce strict validation of the OAuth `state` parameter on authorization error
  responses. Error responses that are missing `state` or have a mismatched `state`
  are now rejected as `state_mismatch` instead of being processed as the original
  error. This closes a cross-site request forgery vulnerability in the error branch.

## [1.0.0]

### Added

- Initial release of the KRDPASS Auth Android SDK: app-to-app SSO with explicit-intent
  launch, provider signing-certificate pinning, PKCE, PAR, client-only (`signIn`) and
  server-mediated (`authenticate`) flows, JWKS-based ID-token verification (issuer /
  audience / expiry / nonce), and token refresh / revoke / userinfo helpers.
- Published to Maven Central as `krd.pass:krdpass-auth`: consumers resolve it with
  `mavenCentral()` and no token.
