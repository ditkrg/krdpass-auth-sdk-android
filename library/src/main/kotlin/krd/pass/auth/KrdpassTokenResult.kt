package krd.pass.auth

/**
 * Result of a successful sign-in operation containing OAuth tokens.
 *
 * This is returned by [KrdpassAuth.signIn] when the client-only authentication flow completes successfully.
 *
 * @param accessToken The OAuth access token
 * @param idToken The OpenID Connect ID token (optional)
 * @param tokenType The token type (usually "Bearer")
 * @param expiresIn The number of seconds until the access token expires
 * @param refreshToken The OAuth refresh token (optional)
 * @param scope The space-separated list of granted scopes (optional)
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
     * Checks if the access token is expired or will expire within the given clock skew.
     * 
     * @param skewSeconds Number of seconds to subtract from expiration for safety.
     * @return True if expired or about to expire.
     */
    public fun isExpired(skewSeconds: Long = 60): Boolean {
        val now = System.currentTimeMillis()
        val expiresAt = receivedAt + (expiresIn * 1000L)
        return now + (skewSeconds * 1000L) >= expiresAt
    }

    public companion object {
        /**
         * Create a [KrdpassTokenResult] from a map of claims, typically from a backend JSON response.
         * Handles both camelCase and snake_case keys.
         */
        public fun fromMap(map: Map<String, Any?>): KrdpassTokenResult {
            return KrdpassTokenResult(
                accessToken = map["accessToken"] as? String ?: map["access_token"] as? String ?: "",
                idToken = map["idToken"] as? String ?: map["id_token"] as? String,
                tokenType = map["tokenType"] as? String ?: map["token_type"] as? String ?: "Bearer",
                expiresIn = (map["expiresIn"] as? Number ?: map["expires_in"] as? Number)?.toInt() ?: 3600,
                refreshToken = map["refreshToken"] as? String ?: map["refresh_token"] as? String,
                scope = map["scope"] as? String,
                // receivedAt deliberately NOT read from the map: it's a LOCAL clock stamp (when THIS
                // device received the token). A backend-echoed received_at would conflate two clocks
                // and silently corrupt isExpired(); the constructor default stamps it correctly.
            )
        }
    }
    /**
     * Returns a redacted string representation that doesn't expose sensitive token values.
     */
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
