# Contributing to KRDPASS Android SDK

This is the standalone repository for the KRDPASS Android SDK.

## Setup

```bash
git clone https://github.com/ditkrg/krdpass-auth-sdk-android.git
cd krdpass-auth-sdk-android
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
