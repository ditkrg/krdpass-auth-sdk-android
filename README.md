# KRDPASS Auth SDK (Android)

Sign in with KRDPASS for native Android apps. The SDK launches the installed KRDPASS
identity app with an explicit intent and receives the result through the Activity-result
API. It is not a browser or WebView flow.

## Getting access

KRDPASS credentials are approval-based, not self-service, because integrations can reach
citizen identity data. Email `integration@pass.krd` with:

- Your Android package name and the SHA-256 fingerprint of your signing certificate
- The scopes you need
- Your HTTPS `redirectUri`

You get back a `clientId`. Refresh tokens (`refreshTokens`, `revokeToken`) are approved
separately and are usually off for a new integration; ask if you need them.

Protocol reference:
<https://docs.digital.gov.krd/software-development/04-interoperability/11-krdpass-sign-in-with-krdpass.html>

## Requirements

- `minSdk` 24, `compileSdk` 36, JDK 17
- A `clientId`, approved scopes, and an HTTPS `redirectUri`

## Install

```kotlin
dependencies {
    implementation("krd.pass:krdpass-auth:1.5.0")
}
```

Published to Maven Central, which is in a new Android project's repositories by default.
No token and no extra repository.

## Platform setup

Nothing to add to your manifest. The SDK's own manifest declares the `INTERNET` permission
it needs for the CAS calls and the `<queries>` element Android 11+ requires to launch the
KRDPASS app; the manifest merger propagates both into yours.

Your Activity does have to be registered so the SDK can receive the launch result.

## Quickstart

**1. Initialize once**, in `Application.onCreate` or your launch Activity:

```kotlin
KrdpassAuth.initialize(
    KrdpassConfig(
        clientId = "your-client-id",
        redirectUri = "https://auth.your-app.example.com/callback",
        environment = KrdpassEnvironment.Production,
    )
)
```

**2. Register your Activity** in `onCreate`, before it reaches STARTED:

```kotlin
KrdpassAuth.register(this)
```

Miss this and every flow fails with `platform_error`.

**3a. Client-only sign-in.** Client-only sign-in needs a public client, and none is currently
issued for any integration, so use the server-mediated flow (3b). It is documented here because
the API ships: the SDK runs PKCE, PAR and the token exchange itself and hands you tokens.

```kotlin
val tokens = KrdpassAuth.signIn(scopes = listOf("openid", "profile"))
```

That is a `suspend` function and throws `KrdpassError` on failure. From Java, or outside a
coroutine, use the callback form:

```kotlin
KrdpassAuth.signIn(
    scopes = listOf("openid", "profile"),
    callback = object : SignInCallback {
        override fun onSuccess(tokens: KrdpassTokenResult) { /* tokens.accessToken */ }
        override fun onFailure(error: Throwable) { /* see Error handling */ }
    },
)
```

**3b. Server-mediated sign-in.** Your backend runs PAR and the token exchange; the SDK
launches KRDPASS and returns the authorization code. PKCE and `state` are yours: generate
both in the app, send only the `codeChallenge` and the `state` to your backend, and hold the
`codeVerifier` until the exchange. Pass that same `state` back into `authenticate`, or the
SDK fails closed with `invalid_request`.

```kotlin
val pkce = KrdpassAuth.generatePkcePair()
val state = KrdpassAuth.generateState()

// Your backend runs the PAR with pkce.codeChallenge and state, and returns the request_uri.
val requestUri = yourBackend.getRequestUri(pkce.codeChallenge, state)

KrdpassAuth.authenticate(requestUri = requestUri, state = state) { result ->
    when (result) {
        is AuthResult.Success -> {
            // send result.code + pkce.codeVerifier + result.state to your backend
        }
        is AuthResult.Cancelled -> { /* usually no UI needed */ }
        is AuthResult.Timeout -> { /* offer retry */ }
        is AuthResult.Busy -> { /* ignore or queue */ }
        is AuthResult.Error ->
            // A deny reported by KRDPASS on the redirect is NOT Cancelled: it arrives here,
            // as Error with code "cancelled". result.isCancelled covers both shapes.
            if (result.isCancelled) { /* usually no UI needed */ }
            else { /* result.code, result.installUrl */ }
    }
}
```

Both entry points take `timeoutMillis: Long`, defaulting to
`KrdpassAuth.DEFAULT_TIMEOUT_MILLIS` (5 minutes).

### Recovering an abandoned flow

The most common real-world failure in app-to-app sign-in is the user switching back to your
app without finishing in KRDPASS. Nothing arrives in that case, so the flow sits pending
until its timeout (5 minutes by default), and a retry in the meantime reports `busy`. Call
`cancelPendingAuthentication` when your app returns to the foreground mid-flow to settle
the pending call as a cancellation and free the SDK for a fresh attempt:

```kotlin
KrdpassAuth.cancelPendingAuthentication(timeout = false)
```

Pass `timeout = true` to settle it as a timeout instead, if your own deadline fired.

### Logging

Nothing is logged until you install a logger. Tokens, authorization codes and PKCE values
are redacted before they reach it.

```kotlin
KrdpassAuth.logger = KrdpassLogger { level, message -> Log.d("KRDPASS", "[$level] $message") }
```

### Launching from your own host

If you drive the launch yourself instead of using `register` (a React Native bridge, a
custom host), `startAuthentication` returns the intent and the launch options. **Pass both.**
The options carry the Android identity-sharing request that lets KRDPASS attribute the
result to your app:

```kotlin
when (val launch = KrdpassAuth.startAuthentication(this, config, requestUri, state)) {
    is KrdpassAuth.AuthLaunch.Ready ->
        startActivityForResult(launch.intent, REQUEST_KRDPASS, launch.activityOptions)
    is KrdpassAuth.AuthLaunch.Failure -> handleError(launch.error)
}
```

Deliver the result to `KrdpassAuth.handleAuthorizationResult` with the same `state`.
`getUserInfo`, `refreshTokens`, `revokeToken` and `verifyToken` also have overloads taking
`clientId` and `environment` explicitly, for hosts that never call `initialize`.

For a client-only flow from your own host, the stateless pair `startSignIn`/`finishSignIn`
runs the same PKCE, PAR, exchange and id_token validation without `register`: `startSignIn`
returns the launch plus a single-use `SignInPending` you hold and pass back:

```kotlin
val (launch, pending) = KrdpassAuth.startSignIn(activity, config)
if (launch is KrdpassAuth.AuthLaunch.Ready) {
    activity.startActivityForResult(launch.intent, requestKrdpass, launch.activityOptions)
}

// Later, in your Activity-result handler:
val tokens = KrdpassAuth.finishSignIn(resultCode, data, config, pending)
```

## Error handling

`signIn` fails with a sealed `KrdpassError`: `UserCancelled`, `Timeout`, `Busy`,
`ConfigurationError`, `NetworkError`, or `AuthenticationFailed` (which additionally carries an
`installUrl` for `provider_not_installed`). Every case exposes `code`, the wire string from the
table below, so you can branch on it without matching the subclass. It is null only on an
`AuthenticationFailed` that carried no structured code.

Branch on `code == "cancelled"` to detect cancellation, not on the `UserCancelled` subclass
alone: `UserCancelled` means the user returned without responding, while a deny reported by
KRDPASS on the redirect arrives as `AuthenticationFailed` with `code == "cancelled"`. The code
covers both; the subclass covers one.

`authenticate` delivers an `AuthResult`: `Success` (with `code` and `state`), `Cancelled`,
`Timeout`, `Busy`, or `Error` (with a typed `code: AuthErrorCode?` and an optional
`installUrl`).

Both draw their codes from the table below (each surfaces the subset its flow can produce), and
the last row is the one `verifyToken` adds. The Flutter and React Native wrappers layer four
per-call fallback codes of their own (`authentication_failed`, `refresh_failed`, `revoke_failed`,
`user_info_failed`) on top of this set; see their READMEs.

| Code | Meaning | Typical handling |
| --- | --- | --- |
| `cancelled` | User cancelled or declined in KRDPASS. `access_denied`, `user_cancelled`, `login_required` and `consent_denied` are rewritten to this before you see them, so branch on `cancelled` alone | Usually no UI needed |
| `timeout` | Auth window elapsed | Offer retry |
| `busy` | Another authentication is in progress | Ignore or queue |
| `state_mismatch` | Returned state differs from expected (possible CSRF/response injection) | Fail closed and restart |
| `invalid_redirect` | Redirect URI does not match the exact configured endpoint (scheme, host, port, path, and fixed query) | Check onboarding config |
| `issuer_mismatch` | Response carried an RFC 9207 `iss` that is not the configured environment's authorization server (possible mix-up attack) | Fail closed and restart |
| `nonce_mismatch` | The id_token carried a `nonce` that is not the one this client sent (possible token replay) | Fail closed and restart |
| `invalid_id_token` | The id_token failed verification: signature, `iss`, `aud`, `exp`, or it was absent from the token response. Also thrown by `verifyToken` | Log and report |
| `invalid_request` | Malformed or blank request parameters | Fix the integration |
| `request_expired` | The request_uri expired inside KRDPASS (NOT a cancellation) | Restart with a fresh PAR request |
| `launch_failed` | The KRDPASS app could not be launched | Retry or check installation |
| `provider_not_installed` | KRDPASS app not installed (`installUrl` is provided) | Open it |
| `no_code` | Provider returned no authorization code | Restart the flow |
| `network_error` | Network failure during token exchange | Safe to retry |
| `platform_error` | Platform-level failure such as an unregistered caller | Log and report |
| `verification_failed` | `verifyToken` failed for a reason that is neither a signature or claim failure nor an unfetchable JWKS | Log and report |

The SDK accepts a result only when it returns to your exact registered redirect endpoint:
scheme, host, effective port, encoded path and any fixed query entries must all match.
OAuth response parameters may be appended; duplicates and overrides of a fixed entry are
rejected.

`verifyToken` is a `suspend` function that checks an ID token's signature against JWKS, plus
its expiry, its audience (your `clientId`) and its issuer (the environment's authorization
server). The `aud` check is exact, not containment: the token's `aud` must be exactly your
`clientId`, so an ID token listing any additional audience is rejected. It fails with
`KrdpassError.AuthenticationFailed` carrying one of three codes, the
same three the other SDKs use here: `invalid_id_token` for a signature, claim or expiry
failure, `network_error` when the JWKS could not be fetched, and `verification_failed` for
anything else. Its `clockSkewSeconds` is clamped to 0..300, so no argument can switch the
expiry check off. `decodeTokenUnverified` does not verify anything, must never drive an
authorization decision, and is the one entry point that throws a plain
`IllegalArgumentException` (when the string is not a parseable JWT) rather than a
`KrdpassError`.

## Tokens, scopes and user info

Scope strings have constants in `KrdpassScopes`, so a typo is a compile error instead of an
`invalid_scope` at runtime:

```kotlin
val scopes = listOf(KrdpassScopes.OPENID, KrdpassScopes.PROFILE, KrdpassScopes.CITIZEN_IDENTITY)
```

`KrdpassTokenResult.isExpired()` reports whether the access token is expired or expires
within the skew (60 seconds by default), measured against the device wall clock:

```kotlin
if (tokens.isExpired()) { /* refresh before calling your API */ }
```

`KrdpassUserInfo.citizenFullName` joins the four citizen name parts in registry order,
dropping blank parts; it is null when no part carries a value:

```kotlin
val displayName = userInfo.citizenFullName ?: userInfo.name
```

## Token storage

The SDK never persists tokens. Store the refresh token encrypted with a key held in the
Android Keystore, never in plain `SharedPreferences`. Note that
`androidx.security:security-crypto` (`EncryptedSharedPreferences`, `MasterKey`) was deprecated
in 1.1.0 in favour of platform APIs and direct Android Keystore use, so do not adopt it for
new work. Full guidance:
[Token Storage](https://github.com/ditkrg/krdpass-auth-samples/blob/main/docs/TOKEN-STORAGE.md).

## Samples

Runnable Android, iOS, Flutter and React Native samples, plus a reference backend, are in
[krdpass-auth-samples](https://github.com/ditkrg/krdpass-auth-samples).

## Development

```bash
./gradlew :library:check
```

That runs the tests, Android lint, detekt and `apiCheck`, which compares the compiled public
API against `library/api/library.api`. After a deliberate API change, regenerate the baseline
with `./gradlew :library:apiDump`.

## License

[MIT](LICENSE) (c) KRG-DIT.
