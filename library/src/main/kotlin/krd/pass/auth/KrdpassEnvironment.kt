package krd.pass.auth

/** The KRDPASS environment to use for authentication. */
public enum class KrdpassEnvironment(
    public val authUrl: String,
    public val authServerUrl: String,
    public val userInfoEndpoint: String,
    public val tokenEndpoint: String,
    public val revocationEndpoint: String,
    public val parEndpoint: String,
    public val jwksEndpoint: String,
    /** Android package name of the KRDPASS provider app for this environment. */
    public val providerPackage: String,
    /**
     * SHA-256 fingerprints (colon-separated hex, uppercase) of the KRDPASS app signing
     * certificate(s) for this environment. The SDK verifies the installed KRDPASS app
     * has one of these certs before launching it.
     *
     * These are PINS: build-time trust anchors. They MUST be hardcoded, never fetched at
     * runtime: fetching the pin over the network you are trying to defend defeats the purpose
     * and adds an offline/fail-open failure mode. The canonical public source is the KRDPASS
     * Digital Asset Links file, which publishes the on-device Play App Signing cert(s):
     *   Production:  https://app.pass.krd/.well-known/assetlinks.json
     *   Development: https://app.krdpass.dev.krd/.well-known/assetlinks.json
     * (Equivalently: Play Console > App > Setup > App signing > App signing key certificate.)
     *
     * Keep this a Set: to survive a Play App Signing key rotation, ship a release containing
     * BOTH the outgoing and incoming fingerprints before the on-device cert flips, then drop
     * the retired one later (a match against any one entry passes).
     *
     * An empty set means "no pin configured". In [Development] that skips the check (local/debug
     * ergonomics); in [Production] the SDK fails closed rather than launch unpinned (see
     * ProviderVerifier.checkInstalled). Never ship Production with an empty set.
     */
    public val providerSigningCertsSha256: Set<String>,
    /**
     * The web URL for this environment. Opening it in a browser takes users to the KRDPASS
     * install page when the app is not present, or opens the app if already installed.
     * Surface this URL when returning a `provider_not_installed` error so integrators can
     * prompt the user to install KRDPASS.
     */
    public val installUrl: String,
) {
    /** Production environment (app.pass.krd), for live apps distributed to end users. */
    Production(
        authUrl = "https://app.pass.krd/connect/authorize",
        authServerUrl = "https://account.id.krd",
        userInfoEndpoint = "https://account.id.krd/connect/userinfo",
        tokenEndpoint = "https://account.id.krd/connect/token",
        revocationEndpoint = "https://account.id.krd/connect/revocation",
        parEndpoint = "https://account.id.krd/connect/par",
        jwksEndpoint = "https://account.id.krd/.well-known/openid-configuration/jwks",
        providerPackage = "krd.pass",
        // Play App Signing on-device cert, transcribed from
        // https://app.pass.krd/.well-known/assetlinks.json. Do NOT fetch at runtime.
        providerSigningCertsSha256 = setOf(
            "38:71:E1:CA:9D:3E:00:AD:9F:C9:4C:25:F8:00:0C:8F:96:EA:33:92:43:9B:9F:0C:30:52:0D:05:3E:65:6F:D2",
        ),
        installUrl = "https://app.pass.krd",
    ),

    /** Development environment (app.krdpass.dev.krd), for testing and development. */
    Development(
        authUrl = "https://app.krdpass.dev.krd/connect/authorize",
        authServerUrl = "https://auth.dev.krd",
        userInfoEndpoint = "https://auth.dev.krd/connect/userinfo",
        tokenEndpoint = "https://auth.dev.krd/connect/token",
        revocationEndpoint = "https://auth.dev.krd/connect/revocation",
        parEndpoint = "https://auth.dev.krd/connect/par",
        jwksEndpoint = "https://auth.dev.krd/.well-known/openid-configuration/jwks",
        providerPackage = "krd.pass.dev",
        // Play App Signing cert + the upload key, transcribed from
        // https://app.krdpass.dev.krd/.well-known/assetlinks.json. Do NOT fetch at runtime.
        // The second (upload-key) value lets locally-built debug APKs verify too.
        providerSigningCertsSha256 = setOf(
            "2A:56:0A:45:19:F6:03:BE:BF:7E:5D:16:98:91:6C:D5:E0:9A:72:89:C2:A4:F4:F7:C9:FA:C4:51:4F:D1:74:B2",
            "BF:51:A2:D4:33:06:53:45:33:D6:61:EC:54:F8:C4:F8:A0:48:56:9C:39:88:BD:21:C8:EE:73:42:7F:95:ED:51",
        ),
        installUrl = "https://app.krdpass.dev.krd",
    )
}
