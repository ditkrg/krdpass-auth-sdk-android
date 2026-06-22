# Contributing to KRDPASS Android SDK

This Android SDK is maintained inside the monorepo at `packages/krdpass_auth_android`.

## Setup

```bash
git clone https://github.com/ditkrg/krdpass-auth-sdk.git
cd krdpass-auth-sdk/packages/krdpass_auth_android
```

## Prerequisites

- JDK 17+
- Android Studio Iguana+
- Gradle wrapper (included)

## Validate Changes

```bash
./gradlew clean test --no-daemon
```

If you changed the example app:

```bash
cd example
./gradlew assembleDebug --no-daemon
```

## Pull Request Expectations

1. Keep changes focused and documented.
2. Add or update tests for behavior changes.
3. Update docs when public behavior changes.
4. Do not commit secrets, keystores, or local machine config files.
