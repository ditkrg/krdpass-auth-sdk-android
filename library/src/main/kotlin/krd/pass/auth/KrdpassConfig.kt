package krd.pass.auth

import android.net.Uri
import androidx.core.net.toUri

/**
 * Configuration for KRDPASS authentication.
 *
 * @param clientId Your OAuth client ID.
 * @param redirectUri Your app's redirect URI registered with the OAuth provider.
 * @param environment The KRDPASS environment to target.
 */
public data class KrdpassConfig(
    public val clientId: String,
    public val redirectUri: String,
    public val environment: KrdpassEnvironment = KrdpassEnvironment.Production
) {
    override fun toString(): String {
        return "KrdpassConfig(clientId=[REDACTED], redirectUri=[REDACTED], environment=$environment)"
    }

    /**
     * Check that an authorization response is for this exact configured redirect endpoint: apart
     * from OAuth response parameters, the scheme, host, effective port, encoded path, and
     * configured query entries must be unchanged. Look-alike paths, configured-query overrides,
     * and ambiguous duplicate response parameters are rejected.
     */
    public fun isValidRedirectUri(uri: Uri): Boolean {
        return RedirectUriValidator.matches(redirectUri.toUri(), uri)
    }

    public fun isValidRedirectUri(url: String): Boolean = isValidRedirectUri(url.toUri())
}

private object RedirectUriValidator {
    fun matches(configuredUri: Uri, returnedUri: Uri): Boolean =
        parseQuery(configuredUri.encodedQuery)?.let { configuredQuery ->
            parseQuery(returnedUri.encodedQuery)?.let { returnedQuery ->
                matchesRedirectBase(configuredUri, returnedUri) &&
                    hasValidResponseQuery(configuredQuery, returnedQuery)
            }
        } ?: false

    private fun matchesRedirectBase(configuredUri: Uri, returnedUri: Uri): Boolean =
        isSafeRedirect(configuredUri) &&
            isSafeRedirect(returnedUri) &&
            configuredUri.scheme.equals(returnedUri.scheme, ignoreCase = true) &&
            configuredUri.host.equals(returnedUri.host, ignoreCase = true) &&
            effectivePort(configuredUri) == effectivePort(returnedUri) &&
            configuredUri.encodedPath.orEmpty() == returnedUri.encodedPath.orEmpty()

    private fun isSafeRedirect(uri: Uri): Boolean =
        uri.isHierarchical &&
            uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.userInfo == null &&
            uri.encodedFragment == null &&
            isValidPercentEncoding(uri.encodedPath) &&
            isValidPercentEncoding(uri.encodedQuery)

    private fun effectivePort(uri: Uri): Int = if (uri.port == -1) HTTPS_DEFAULT_PORT else uri.port

    private fun hasValidResponseQuery(
        configuredQuery: List<QueryEntry>,
        returnedQuery: List<QueryEntry>,
    ): Boolean {
        val remaining = configuredQuery.takeIf { entries -> entries.none { it.name in OAUTH_RESPONSE_PARAMETERS } }
            ?.let { removeConfiguredEntries(it, returnedQuery) }
        return remaining?.let { responseEntries ->
            val hasNoDuplicates = responseEntries.groupingBy { it.name }.eachCount().values.none { it > ONE_ENTRY }
            val configuredNames = configuredQuery.mapTo(mutableSetOf()) { it.name }
            val doesNotOverrideConfiguredQuery = responseEntries.none { it.name in configuredNames }
            val isNotAmbiguous = responseEntries.none { it.name == "code" } || responseEntries.none { it.name == "error" }
            val hasNoBlankSecurityValues = responseEntries
                .filter { it.name in REQUIRED_NON_BLANK_RESPONSE_PARAMETERS }
                .all { !it.value.isNullOrBlank() }
            hasNoDuplicates &&
                doesNotOverrideConfiguredQuery &&
                isNotAmbiguous &&
                hasNoBlankSecurityValues
        } ?: false
    }

    private fun removeConfiguredEntries(
        configuredQuery: List<QueryEntry>,
        returnedQuery: List<QueryEntry>,
    ): List<QueryEntry>? {
        val remaining = returnedQuery.toMutableList()
        configuredQuery.forEach { configuredEntry ->
            val index = remaining.indexOf(configuredEntry)
            if (index == -1) return null
            remaining.removeAt(index)
        }
        return remaining
    }

    private fun parseQuery(encodedQuery: String?): List<QueryEntry>? {
        val encodedEntries = encodedQuery?.takeIf { it.isNotEmpty() }?.split('&') ?: return emptyList()
        return encodedEntries.map(::parseQueryEntry).takeIf { it.all { entry -> entry != null } }
            ?.filterNotNull()
    }

    private fun parseQueryEntry(encodedEntry: String): QueryEntry? {
        val separator = encodedEntry.indexOf('=')
        val encodedName = if (separator == -1) encodedEntry else encodedEntry.substring(0, separator)
        val encodedValue = if (separator == -1) null else encodedEntry.substring(separator + 1)
        val isValid = encodedName.isNotEmpty() &&
            isValidPercentEncoding(encodedName) &&
            isValidPercentEncoding(encodedValue)
        return if (isValid) QueryEntry(Uri.decode(encodedName), encodedValue?.let(Uri::decode)) else null
    }

    /**
     * Rejects syntactically malformed percent escapes. Percent-formed but invalid UTF-8 is left
     * alone: [Uri.decode] normalizes it to replacement characters.
     */
    private fun isValidPercentEncoding(value: String?): Boolean =
        value?.let { !INVALID_PERCENT_ENCODING.containsMatchIn(it) } ?: true

    private data class QueryEntry(val name: String, val value: String?)

    private const val HTTPS_DEFAULT_PORT: Int = 443
    private const val ONE_ENTRY: Int = 1
    private val INVALID_PERCENT_ENCODING: Regex = Regex("%(?![0-9A-Fa-f]{2})")
    private val OAUTH_RESPONSE_PARAMETERS: Set<String> = setOf(
        "code",
        "state",
        "error",
        "error_description",
        "error_uri",
        "iss",
    )
    // "If present, must not be blank", never "must be present". This set is the cross-SDK
    // contract, mirrored in src/test/resources/redirect-validation.json.
    private val REQUIRED_NON_BLANK_RESPONSE_PARAMETERS: Set<String> = setOf("code", "state", "error", "iss")
}
