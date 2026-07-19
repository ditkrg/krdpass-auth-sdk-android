package krd.pass.auth

import android.net.Uri
import androidx.core.net.toUri

/**
 * Configuration for KRDPASS authentication.
 *
 * @param clientId Your OAuth client ID. Required for OAuth authorization requests.
 * @param redirectUri Your app's redirect URI registered with the OAuth provider.
 *                    Used to validate the redirect URL returned via the KRDPASS activity result.
 * @param environment The KRDPASS environment to target. Defaults to [KrdpassEnvironment.Production].
 */
public data class KrdpassConfig(
    public val clientId: String,
    public val redirectUri: String,
    public val environment: KrdpassEnvironment = KrdpassEnvironment.Production
) {
    /**
     * Returns a string representation that doesn't expose sensitive configuration.
     */
    override fun toString(): String {
        return "KrdpassConfig(clientId=[REDACTED], redirectUri=[REDACTED], environment=$environment)"
    }
    /**
     * Check if a given URI matches the configured redirect URI pattern.
     * Enforces HTTPS-only redirects and requires host match.
     * Path is NOT validated - any HTTPS path on the same host is allowed.
     */
    public fun isValidRedirectUri(uri: Uri): Boolean {
        val configuredUri = redirectUri.toUri()
        if (configuredUri.scheme != "https") return false
        if (configuredUri.host.isNullOrBlank()) return false
        
        if (uri.scheme != "https") return false
        if (uri.host?.isNotBlank() != true) return false
        if (uri.host != configuredUri.host) return false

        // Ports must match (both default to -1 "unspecified", so a plain inequality covers all cases).
        if (configuredUri.port != uri.port) return false

        return true
    }

    public fun isValidRedirectUri(url: String): Boolean = isValidRedirectUri(url.toUri())
}
