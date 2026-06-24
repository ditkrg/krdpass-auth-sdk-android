## 1.0.0

* Initial release of the KRDPASS Auth Android SDK.
* `KrdpassError.AuthenticationFailed` now carries a structured `code`
  (`state_mismatch`, `no_code`, `provider_not_installed`, `invalid_id_token`,
  `nonce_mismatch`, …) so callers can branch without parsing the message —
  matching the Flutter/React Native SDKs.
* `verifyToken` now takes `idToken` and derives the audience from the configured
  `clientId` (parity with Flutter/React Native).
* Added `cancelPendingAuthentication(timeout)`; `cancel()` / `timeout()` are now
  deprecated aliases.