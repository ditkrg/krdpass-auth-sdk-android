# KRDPASS Auth SDK (Android)

Sign in with KRDPASS for native Android apps. The SDK launches the installed KRDPASS
identity app with an explicit intent and receives the result through the Activity-result
API. It is not a browser or WebView flow.

Full integration guide, onboarding, error codes and security requirements:
**[KRDPASS documentation](https://docs.digital.gov.krd/software-development/04-interoperability/11-krdpass-sign-in-with-krdpass.html)**

## Requirements

- `minSdk` 24, `compileSdk` 36, JDK 17
- Compiled with Kotlin 2.2.21. Your app can use a newer Kotlin.
- A `clientId`, approved scopes, and an HTTPS `redirectUri`. See
  [Getting started](https://docs.digital.gov.krd/software-development/04-interoperability/12-krdpass-getting-started.html).

## Install

```kotlin
dependencies {
    implementation("krd.pass:krdpass-auth:1.6.0")
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

Miss this and `authenticate` fails with `platform_error`, `signIn` with `invalid_request`.

**3. Sign in.** Your backend runs PAR and the token exchange; the SDK launches KRDPASS and
returns the authorization code. PKCE and `state` are yours: generate both in the app, send
only the `codeChallenge` and the `state` to your backend, and hold the `codeVerifier` until
the exchange. Pass that same `state` back into `authenticate`, or the SDK fails closed with
`invalid_request`.

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

`authenticate` takes `timeoutMillis: Long`, defaulting to
`KrdpassAuth.DEFAULT_TIMEOUT_MILLIS` (5 minutes).

The client-only `signIn` API ships but needs a public client, which is not currently issued
to any integration. Use the flow above.

### Recovering an abandoned flow

The most common real-world failure in app-to-app sign-in is the user switching back to your
app without finishing in KRDPASS. Nothing arrives in that case, so the flow sits pending
until its timeout, and a retry in the meantime reports `busy`. Call
`cancelPendingAuthentication` when your app returns to the foreground mid-flow:

```kotlin
KrdpassAuth.cancelPendingAuthentication(timeout = false)
```

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

## Error handling

Every error code, what emits it, and how to handle it:
[Testing and go-live](https://docs.digital.gov.krd/software-development/04-interoperability/14-krdpass-testing-and-go-live.html).

## Tokens and identity

`getUserInfo`, `refreshTokens`, `revokeToken`, `verifyToken` and `decodeTokenUnverified` are
`suspend` functions on `KrdpassAuth`. Scopes, claims and token handling rules:
[Reference](https://docs.digital.gov.krd/software-development/04-interoperability/15-krdpass-reference.html).

The SDK never persists tokens. Storage requirements:
[Token storage](https://github.com/ditkrg/krdpass-auth-samples/blob/main/docs/TOKEN-STORAGE.md).

## Samples

Runnable apps for all five platforms, plus a reference backend:
[krdpass-auth-samples](https://github.com/ditkrg/krdpass-auth-samples).

## Development

```bash
./gradlew :library:check
```

Runs the tests, lint, detekt and the binary-compatibility check.

## License

MIT. See [LICENSE](LICENSE).
