package krd.pass.auth

import android.net.Uri
import androidx.core.net.toUri

/**
 * Configuration for KRDPass authentication.
 *
 * @param redirectUri Your app's redirect URI registered with the OAuth provider.
 *                    Used to validate the redirect URL returned via the KRDPass activity result.
 * @param clientId Your OAuth client ID. Required for OAuth authorization requests.
 */
data class KrdpassConfig(
    val clientId: String,
    val redirectUri: String,
    val environment: KrdpassEnvironment = KrdpassEnvironment.Production
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
    fun isValidRedirectUri(uri: Uri): Boolean {
        val configuredUri = redirectUri.toUri()
        if (configuredUri.scheme != "https") return false
        if (configuredUri.host.isNullOrBlank()) return false
        
        if (uri.scheme != "https") return false
        if (uri.host?.isNotBlank() != true) return false
        if (uri.host != configuredUri.host) return false

        val configuredPort = configuredUri.port
        val incomingPort = uri.port
        if (configuredPort != -1 || incomingPort != -1) {
            if (configuredPort != incomingPort) return false
        }

        return true
    }

    fun isValidRedirectUri(url: String): Boolean = isValidRedirectUri(url.toUri())
}
