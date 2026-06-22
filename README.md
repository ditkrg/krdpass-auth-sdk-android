# KRDPASS Auth SDK (Android)

Official native Android SDK for **Sign in with KRDPASS** — app-to-app SSO with the
KRDPASS identity app (explicit-intent launch + signing-cert pinning, not a browser flow).

## Requirements

- Android Studio Iguana+
- JDK 17+
- Android `minSdk` 24+
- A registered KRDPASS client (`clientId`, approved scopes, HTTPS `redirectUri`)

## Install (GitHub Packages)

The SDK is published to **GitHub Packages** (private; no Maven Central / JitPack). Add the
repository and credentials in your `settings.gradle.kts` (or app `build.gradle.kts`):

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/ditkrg/krdpass-auth-sdk-android")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.token").orNull ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
```

Provide a GitHub Personal Access Token with the **`read:packages`** scope via
`~/.gradle/gradle.properties` (`gpr.user` / `gpr.token`) or the `GITHUB_ACTOR` /
`GITHUB_TOKEN` environment variables. Then add the dependency:

```kotlin
dependencies {
    implementation("krd.pass:krdpass-auth:1.0.0")
}
```

## Quickstart

Initialize once (e.g. in `Application.onCreate`), register your Activity, then launch a flow:

```kotlin
// 1. Initialize
KrdpassAuth.initialize(
    KrdpassConfig(
        clientId = "your-client-id",
        redirectUri = "https://auth.your-app.example.com/callback",
        environment = KrdpassEnvironment.Production,
    )
)

// 2. Register in your Activity's onCreate (before STARTED)
KrdpassAuth.register(this)

// 3a. Client-only flow — SDK does PKCE + PAR + token exchange and returns tokens
KrdpassAuth.signIn(scopes = listOf("openid", "profile")) { result ->
    result.onSuccess { tokens -> /* tokens.accessToken, tokens.idToken */ }
          .onFailure { e -> /* handle KrdpassError */ }
}

// 3b. Backend-mediated flow — your server runs PAR + exchange; SDK returns the code
KrdpassAuth.authenticate(requestUri = requestUriFromBackend, state = state) { authResult ->
    // send authResult code + state to your backend to exchange for tokens
}
```

> Helpers that do **not** verify a token are intentionally named `decodeTokenUnverified` —
> never use their output for trust decisions; use `verifyToken` (JWKS) instead.

## Integration Notes

- Recommended production flow: server-mediated PAR + token exchange (`authenticate`).
- Android callback completion uses the Activity/Intent result from the explicit KRDPASS launch.
- `redirectUri` is still required because the OAuth server policy requires it.

## Required Onboarding Inputs

- `clientId`
- Approved scopes
- HTTPS `redirectUri`
- Android package name and SHA-256 signing fingerprint

## Security Notes

- Keep `client_secret` and private keys server-side.
- Do not commit keystores, private keys, or `.env` files.

## Backend & Protocol Reference

- Integration guide: <https://docs.digital.gov.krd/software-development/04-interoperability/11-krdpass-sign-in-with-krdpass.html>
