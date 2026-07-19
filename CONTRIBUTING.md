# Contributing to the KRDPASS Android SDK

The library lives at the root of this repository (`library/`), with an optional sample app
under `example/`.

## Setup

```bash
git clone https://github.com/ditkrg/krdpass-auth-sdk-android.git
cd krdpass-auth-sdk-android
```

## Prerequisites

- JDK 17+
- Android Studio 2025.2 (Otter) or newer; the project builds with AGP 9.2
- Gradle wrapper (included)

## Validate Changes

```bash
./gradlew :library:test :library:lint
```

If the sample app is present (`example/`):

```bash
./gradlew :example:app:assembleDebug
```

## Pull Request Expectations

1. Keep changes focused and documented.
2. Add or update tests for behavior changes.
3. Update docs when public behavior changes.
4. Do not commit secrets, keystores, or local machine config files.
