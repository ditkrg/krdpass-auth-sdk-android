# KRDPASS Auth SDK (Android)

Official native Android SDK for **Sign in with KRDPASS**: app-to-app SSO with the
KRDPASS identity app (explicit-intent launch + signing-cert pinning, not a browser flow).

KRDPASS credentials are approval-based, not open self-service: onboarding contact is
`integration@pass.krd`, since integrations may access sensitive citizen identity data.
Keep `client_secret` and signing keys server-side, and use the server-mediated flow for
production.

## Requirements

- Android Studio 2025.2 (Otter) or newer (the project builds with AGP 9.2)
- JDK 17+ (the library targets JDK 17; the sample app in the KRDPASS demos repository uses JDK 21)
- Android `minSdk` 24+
- A registered KRDPASS client (`clientId`, approved scopes, HTTPS `redirectUri`)
- Production and development environments are both supported (`KrdpassEnvironment.Production` / `.Development`)

## Install

The SDK is published to **Maven Central**: no token or extra repository needed.
Ensure `mavenCentral()` is in your repositories (it is, by default in a new Android project):

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
```

Then add the dependency:

```kotlin
dependencies {
    implementation("krd.pass:krdpass-auth:1.1.1")
}
```

## Platform setup

Android 11+ requires apps to declare the packages they launch. The SDK declares the required
`<queries>` element in its own manifest, and Gradle's manifest merger propagates it into your
app automatically, so no manual setup is needed for a normal build. Add the snippet below yourself
only if your build strips or overrides merged manifests:

```xml
<queries>
    <package android:name="krd.pass" />        <!-- Production -->
    <package android:name="krd.pass.dev" />     <!-- Development -->
</queries>
```

The SDK also requires your Activity to be registered (see Quickstart) so it can launch
KRDPASS via an explicit intent and receive the result through the Activity-result API. The
iOS counterpart of this same callback hand-off uses Universal Links instead of an Activity
result: the two are equivalent trust boundaries, just platform-native mechanisms.

## Quickstart

1. **Initialize**, once, e.g. in `Application.onCreate`:

   ```kotlin
   KrdpassAuth.initialize(
       KrdpassConfig(
           clientId = "your-client-id",
           redirectUri = "https://auth.your-app.example.com/callback",
           environment = KrdpassEnvironment.Production,
       )
   )
   ```

   Then register your Activity, in `onCreate` (before `STARTED`). This is required because
   the Activity-result API needs a registered caller to deliver the launch result back to:

   ```kotlin
   KrdpassAuth.register(this)
   ```

2. **Client-only sign-in (no backend)**: the SDK runs PKCE + PAR + token exchange and
   returns tokens directly:

   ```kotlin
   KrdpassAuth.signIn(scopes = listOf("openid", "profile")) { result ->
       result.onSuccess { tokens ->
           // tokens.accessToken, tokens.idToken
       }.onFailure { e ->
           when (e) {
               is KrdpassError.UserCancelled -> { /* usually no UI needed */ }
               is KrdpassError.Timeout -> { /* offer retry */ }
               is KrdpassError.Busy -> { /* ignore or queue */ }
               is KrdpassError.ConfigurationError -> { /* fix the integration */ }
               is KrdpassError.NetworkError -> { /* safe to retry; e.cause has detail */ }
               is KrdpassError.AuthenticationFailed -> {
                   // e.code may be provider_not_installed (e.installUrl set), state_mismatch, etc.
               }
               else -> { /* unknown KrdpassError */ }
           }
       }
   }
   ```

3. **Server-mediated flow (recommended for production)**: your server runs PAR + token
   exchange; the SDK only launches KRDPASS and returns the authorization code:

   ```kotlin
   KrdpassAuth.authenticate(requestUri = requestUriFromBackend, state = state) { authResult ->
       when (authResult) {
           is AuthResult.Success -> {
               // send authResult.code + authResult.state to your backend to exchange for tokens
           }
           is AuthResult.Cancelled -> { /* usually no UI needed */ }
           is AuthResult.Timeout -> { /* offer retry */ }
           is AuthResult.Busy -> { /* ignore or queue */ }
           is AuthResult.Error -> {
               // authResult.code (AuthErrorCode) e.g. state_mismatch, provider_not_installed
               // (authResult.installUrl set for provider_not_installed)
           }
       }
   }
   ```

> Helpers that do **not** verify a token are intentionally named `decodeTokenUnverified`:
> never use their output for trust decisions; use `verifyToken` (JWKS) instead.

## Error handling

| Code | Meaning | Typical handling |
| --- | --- | --- |
| `cancelled` | User cancelled in KRDPASS (`access_denied` / `user_cancelled` / `login_required` / `consent_denied` are classified as cancellation too) | Usually no UI needed |
| `access_denied` | User declined consent (classified as cancellation) | Usually no UI needed |
| `timeout` | Auth window elapsed | Offer retry |
| `busy` | Another authentication is in progress | Ignore or queue |
| `state_mismatch` | Returned state differs from expected (possible CSRF/response injection) | Fail closed and restart |
| `invalid_redirect` | Redirect URI does not match the configured host | Check onboarding config |
| `invalid_request` | Malformed or blank request parameters | Fix the integration |
| `request_expired` | The request_uri expired inside KRDPASS (NOT a cancellation) | Restart with a fresh PAR request |
| `launch_failed` | The KRDPASS app could not be launched | Retry or check installation |
| `provider_not_installed` | KRDPASS app not installed (`installUrl` is provided) | Open it |
| `no_code` | Provider returned no authorization code | Restart the flow |
| `network_error` | Network failure during token exchange | Safe to retry |
| `platform_error` | Platform-level failure such as an unregistered caller | Log and report |

The **client-only** `signIn` flow fails with a typed, sealed `KrdpassError`
(`UserCancelled`, `Timeout`, `Busy`, `ConfigurationError`, `NetworkError`, or
`AuthenticationFailed`, the latter carries a structured `code` such as `state_mismatch`
or `provider_not_installed`, plus an optional `installUrl`). The **server-mediated**
`authenticate` flow delivers an `AuthResult`: branch on `AuthResult.Success` (carries
`code` + `state`) versus `Cancelled` / `Timeout` / `Busy` / `Error` (the latter exposes a
typed `code: AuthErrorCode?` plus an optional `installUrl`).

## Refresh Token Policy

`refreshTokens` and `revokeToken` APIs are available for approved integrations, but refresh
token issuance is high-sensitivity and usually not enabled by default for early integrations.

## Required Onboarding Inputs

- `clientId`
- Approved scopes
- HTTPS `redirectUri`
- Android package name and SHA-256 signing fingerprint

## Example App

A reference Android sample app, demonstrating both the client-only and server-mediated
flows, is maintained in the KRDPASS demos repository.

## Security Notes

- Keep `client_secret` and private keys server-side.
- Never commit secrets, keystores, or `.env` files.

## Backend & Protocol Reference

- Integration guide: <https://docs.digital.gov.krd/software-development/04-interoperability/11-krdpass-sign-in-with-krdpass.html>

## Development

Run the library's unit tests and lint:

```bash
./gradlew :library:test :library:lint
```

See `CONTRIBUTING.md` for the full contributor setup and pull request expectations.

## License

[MIT](LICENSE) (c) KRG-DIT.
