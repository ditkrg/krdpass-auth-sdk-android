# KRDPASS Auth SDK (Android)

Official native Android SDK for **Sign in with KRDPASS**.

## Requirements

- Android Studio Iguana+
- JDK 17+ (example app uses JDK 21 toolchain)
- Android min SDK 23+

## Install from This Repository (v1)

1. Clone the SDK repo:

```bash
git clone https://github.com/ditkrg/krdpass-auth-sdk.git
```

2. In your app `settings.gradle.kts`, include the local SDK build:

```kotlin
includeBuild("../krdpass-auth-sdk/packages/krdpass_auth_android") {
    dependencySubstitution {
        substitute(module("krd.pass:krdpass-auth")).using(project(":library"))
    }
}
```

3. Add dependency in app `build.gradle.kts`:

```kotlin
dependencies {
    implementation("krd.pass:krdpass-auth:1.0.0")
}
```

## Integration Notes

- Recommended production flow: server-mediated PAR + token exchange.
- Android callback completion uses Activity/Intent result.
- `redirectUri` is still required because OAuth server policy requires it.

## Required Onboarding Inputs

- `clientId`
- Approved scopes
- HTTPS `redirectUri`
- Android package name and SHA-256 signing fingerprint

## Example App

- Path: `packages/krdpass_auth_android/example`
- Setup guide: `packages/krdpass_auth_android/example/README.md`

## Security Notes

- Keep `client_secret` and private keys server-side.
- Do not commit key stores, private keys, or `.env` files.

## Related Docs

- Root guide: `../../README.md`
- Integration architecture: `../../docs/INTEGRATION.md`
- Server reference: `../../examples/server/README.md`
