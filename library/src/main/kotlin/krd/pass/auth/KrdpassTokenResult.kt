package krd.pass.auth

/**
 * OAuth tokens from a successful sign-in.
 *
 * @param expiresIn Seconds until the access token expires.
 * @param scope Space-separated list of granted scopes, when returned.
 */
public data class KrdpassTokenResult(
    val accessToken: String,
    val idToken: String?,
    val tokenType: String,
    val expiresIn: Int,
    val refreshToken: String?,
    val scope: String?,
    val receivedAt: Long = System.currentTimeMillis()
) {
    /**
     * True when the access token is expired or expires within [skewSeconds]. Measured against the
     * wall clock, so a device clock change shifts the answer; the authorization server's own `exp`
     * check is the one that decides.
     */
    public fun isExpired(skewSeconds: Long = 60): Boolean {
        val now = System.currentTimeMillis()
        val expiresAt = receivedAt + (expiresIn * MILLIS_PER_SECOND)
        return now + (skewSeconds * MILLIS_PER_SECOND) >= expiresAt
    }

    private companion object {
        private const val MILLIS_PER_SECOND = 1000L
    }

    override fun toString(): String {
        return "KrdpassTokenResult(" +
            "accessToken=[REDACTED], " +
            "idToken=${if (idToken != null) "[REDACTED]" else "null"}, " +
            "tokenType='$tokenType', " +
            "expiresIn=$expiresIn, " +
            "refreshToken=${if (refreshToken != null) "[REDACTED]" else "null"}, " +
            "scope=$scope" +
            ")"
    }
}
