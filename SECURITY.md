# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Email **security@pass.krd** instead, and include:

1. **Description**: a clear description of the vulnerability
2. **Steps to reproduce**: detailed steps to reproduce the issue
3. **Impact**: what an attacker could achieve by exploiting it
4. **Environment**: SDK name/version, platform version, device information
5. **Proof of concept**: if possible

### Our commitment

- We will acknowledge receipt of your report within 48 hours.
- We will provide a more detailed response within 7 days indicating our next steps.
- We will keep you informed about our progress throughout the process.
- We will credit you (with your permission) when the vulnerability is disclosed.

## Notes on two deliberate choices

**A dropped provider fingerprint is not a revocation.** The SDK pins the KRDPASS app's
signing certificate. For a single-signer app it reads Android's
`signingCertificateHistory`, so an app that has rotated its signing key still matches the
fingerprint it used before the rotation. That is Android's intended semantic and it is what
makes a key rotation survivable, but it means removing a retired fingerprint from the pin set
in a later SDK release does not revoke it on devices that already have the rotated app.

**The SDK does not pin the TLS certificate of `account.id.krd`.** Traffic to the
authorization server relies on the platform trust store on minSdk 24 and above. Certificate
pinning here would add an offline failure mode that outlives any release we can ship (a pin
that expires bricks sign-in for every installed app), and the app-to-app leg is already
protected by a different mechanism: the SDK launches the provider through a
`setPackage()`-locked explicit Intent to a package whose APK signing certificate is pinned,
so the authorization request never travels over a network an attacker could intercept.

## Full Security Policy

The complete KRDPASS security policy, including the security model for the
app-to-app authorization flow and redirect validation, is maintained in the
samples repository:
[`docs/SECURITY.md`](https://github.com/ditkrg/krdpass-auth-samples/blob/main/docs/SECURITY.md).
