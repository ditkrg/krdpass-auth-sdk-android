package krd.pass.auth

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.coroutines.executeAsync
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Client for talking directly to CAS: PAR, token exchange, refresh, revoke, and userinfo.
 * Internal on purpose: publishing it would freeze six network methods and their response shapes
 * into the Maven Central ABI for the life of 1.x.
 */
internal class CasClient internal constructor(
    private val clientId: String,
    private val environment: KrdpassEnvironment,
    private val httpClient: OkHttpClient
) {

    /**
     * The single request/response funnel for every CAS endpoint. [parse] runs after the retry
     * loop (a malformed 200 body is the server's answer, retrying cannot change it) but inside
     * the funnel, so a 200 carrying a proxy's HTML reaches the caller as the same permanent
     * CasException a 400 does.
     */
    private suspend fun <T> execute(
        request: Request,
        label: String,
        maxAttempts: Int = 3,
        okStatusCodes: Set<Int> = emptySet(),
        parse: (body: String) -> T,
    ): T {
        val body = retry(maxAttempts) {
            httpClient.newCall(request).executeAsync().use { response ->
                val text = response.body.string()
                if (!response.isSuccessful && response.code !in okStatusCodes) {
                    // Status only: the KrdpassLogger contract promises no raw upstream content.
                    log("ERROR", "$label failed (${response.code})")
                    throw CasException("$label failed (${response.code}): ${parseCasError(text)}", response.code)
                }
                text
            }
        }
        return try {
            parse(body.ifBlank { "{}" })
        } catch (e: JSONException) {
            // No status code: unparseable is permanent, so this classifies as AuthenticationFailed.
            throw CasException("$label returned an unreadable body", cause = e)
        }
    }

    /** Retry [action] with linear backoff, giving up on a permanent status (see the 4xx test). */
    private suspend fun <T> retry(
        maxAttempts: Int = 3,
        initialDelayMillis: Long = 1000L,
        action: suspend () -> T
    ): T {
        var attempt = 0
        while (true) {
            try {
                attempt++
                return action()
            } catch (e: CancellationException) {
                // Cancellation is not a request failure: it must propagate, never be retried.
                throw e
            } catch (e: Exception) {
                if (attempt >= maxAttempts) throw e

                if (e is CasException) {
                    val status = e.statusCode
                    if (status == null) throw e
                    if (status in CLIENT_ERRORS && !e.isRetryable) {
                        throw e
                    }
                }

                log("DEBUG", "Request failed (attempt $attempt/$maxAttempts). Retrying in ${initialDelayMillis * attempt}ms...")
                delay(initialDelayMillis * attempt)
            }
        }
    }

    suspend fun pushAuthorizationRequest(
        codeChallenge: String,
        redirectUri: String,
        scopes: List<String>,
        state: String? = null,
        nonce: String? = null
    ): ParResponse {
        require(codeChallenge.isNotBlank()) { "codeChallenge cannot be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri cannot be blank" }
        require(scopes.isNotEmpty()) { "scopes cannot be empty" }
        val url = environment.parEndpoint
        log("DEBUG", "PAR -> $url (client_id=$clientId, redirect_uri=$redirectUri)")

        val requestBody = FormBody.Builder()
            .add("client_id", clientId)
            .add("response_type", "code")
            .add("redirect_uri", redirectUri)
            .add("scope", scopes.joinToString(" "))
            .add("code_challenge", codeChallenge)
            .add("code_challenge_method", "S256")
            .apply {
                state?.let { add("state", it) }
                nonce?.let { add("nonce", it) }
            }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()

        return execute(request, "PAR request") { body ->
            val json = JSONObject(body)
            val requestUri = json.optString("request_uri")
            if (requestUri.isBlank()) {
                throw CasException("Invalid PAR response: missing or empty request_uri")
            }
            ParResponse(requestUri, json.optInt("expires_in", DEFAULT_PAR_EXPIRES_IN_SECONDS))
        }
    }

    suspend fun exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        redirectUri: String
    ): KrdpassTokenResult {
        require(code.isNotBlank()) { "code cannot be blank" }
        require(codeVerifier.isNotBlank()) { "codeVerifier cannot be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri cannot be blank" }
        val url = environment.tokenEndpoint

        val requestBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("client_id", clientId)
            .add("redirect_uri", redirectUri)
            .add("code", code)
            .add("code_verifier", codeVerifier)
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()

        // An authorization code is single-use, so never retry the exchange (maxAttempts = 1): a
        // blip after the server already consumed the code replays it as an invalid_grant.
        return execute(request, "Token exchange", maxAttempts = 1) { body -> parseTokenResult(body) }
    }

    suspend fun getUserInfo(accessToken: String): KrdpassUserInfo {
        require(accessToken.isNotBlank()) { "accessToken cannot be blank" }

        val url = environment.userInfoEndpoint
        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $accessToken")
            .get()
            .build()

        return execute(request, "UserInfo request") { body -> parseUserInfo(JSONObject(body)) }
    }

    suspend fun refreshTokens(
        refreshToken: String,
        scope: String? = null
    ): KrdpassTokenResult {
        require(refreshToken.isNotBlank()) { "refreshToken cannot be blank" }
        val url = environment.tokenEndpoint

        val requestBody = FormBody.Builder()
            .add("client_id", clientId)
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .apply { if (!scope.isNullOrBlank()) add("scope", scope) }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()
        log("DEBUG", "Refreshing tokens at: $url (client_id=$clientId, refresh_token=[REDACTED])")

        // CAS may rotate refresh tokens (single-use), so never retry (maxAttempts = 1): replaying a
        // consumed token can trip reuse detection and revoke the whole token family.
        return execute(request, "Token refresh", maxAttempts = 1) { body -> parseTokenResult(body) }
    }

    suspend fun revokeToken(
        token: String,
        tokenTypeHint: String? = null
    ) {
        require(token.isNotBlank()) { "token cannot be blank" }
        val url = environment.revocationEndpoint

        val requestBody = FormBody.Builder()
            .add("client_id", clientId)
            .add("token", token)
            .apply { if (!tokenTypeHint.isNullOrBlank()) add("token_type_hint", tokenTypeHint) }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()
        log("DEBUG", "Revoking token at: $url (client_id=$clientId, token=[REDACTED], hint=$tokenTypeHint)")

        // RFC 7009: a successful revocation returns 200; some servers return 204 (no content).
        execute(request, "Token revocation", okStatusCodes = setOf(HTTP_NO_CONTENT)) { }
    }

    /** Best-effort OAuth error string; falls back to the raw body, redacted and bounded. */
    private fun parseCasError(body: String): String {
        if (body.isBlank()) return body
        return try {
            val json = JSONObject(body)
            val error = json.optString("error")
            val description = json.optString("error_description")
            when {
                error.isNotBlank() && description.isNotBlank() -> "$error: ${sanitizeRawBody(description)}"
                error.isNotBlank() -> error
                else -> sanitizeRawBody(body)
            }
        } catch (_: JSONException) {
            sanitizeRawBody(body)
        }
    }

    /**
     * Redact token-shaped runs from upstream CAS text (a raw body, a structured
     * error_description) and cap its length. This text reaches
     * the host app via the [KrdpassError] message; a CAS deployment that echoed a submitted token
     * back in its error body would otherwise send it straight into an app's crash reporter.
     */
    private fun sanitizeRawBody(body: String): String {
        // JWT shape first, so a three-segment token collapses to one marker instead of three.
        return body
            .replace(JWT_SHAPED, REDACTED)
            .replace(LONG_BASE64URL_RUN, REDACTED)
            .bounded()
    }

    /** Fails closed on a missing access_token. */
    private fun parseTokenResult(body: String): KrdpassTokenResult {
        val json = JSONObject(body)
        val accessToken = json.optString("access_token")
        if (accessToken.isBlank()) {
            throw CasException("Invalid token response: missing or empty access_token")
        }
        return KrdpassTokenResult(
            accessToken = accessToken,
            idToken = json.optString("id_token").takeIf { it.isNotBlank() },
            tokenType = json.optString("token_type").takeIf { it.isNotBlank() } ?: "Bearer",
            expiresIn = json.optInt("expires_in", DEFAULT_TOKEN_EXPIRES_IN_SECONDS),
            refreshToken = json.optString("refresh_token").takeIf { it.isNotBlank() },
            scope = json.optString("scope").takeIf { it.isNotBlank() },
        )
    }

    private fun parseUserInfo(json: JSONObject): KrdpassUserInfo {
        // getString throws on an absent `sub` but not an empty one. Reject empty (not
        // whitespace-only) too, matching the iOS, Flutter and RN SDKs.
        val sub = json.getString("sub")
        if (sub.isEmpty()) {
            throw JSONException("Invalid user info response: missing or empty sub field")
        }
        return KrdpassUserInfo(
            sub = sub,
            name = json.optString("name").takeIf { it.isNotBlank() },
            givenName = json.optString("given_name").takeIf { it.isNotBlank() },
            familyName = json.optString("family_name").takeIf { it.isNotBlank() },
            picture = json.optString("picture").takeIf { it.isNotBlank() } ?: json.optString("citizen_profile_picture").takeIf { it.isNotBlank() },
            email = json.optString("email").takeIf { it.isNotBlank() },
            citizenFirst = json.optString("citizen_first").takeIf { it.isNotBlank() },
            citizenSecond = json.optString("citizen_second").takeIf { it.isNotBlank() },
            citizenThird = json.optString("citizen_third").takeIf { it.isNotBlank() },
            citizenSurname = json.optString("citizen_surname").takeIf { it.isNotBlank() },
            citizenProfilePicture = json.optString("citizen_profile_picture").takeIf { it.isNotBlank() },
            birthdate = json.optString("birthdate").takeIf { it.isNotBlank() },
            sexAtBirth = json.optString("sex_at_birth").takeIf { it.isNotBlank() },
            upn = json.optString("upn").takeIf { it.isNotBlank() },
            upns = json.parseUpns(),
            did = json.optString("did").takeIf { it.isNotBlank() },
            raw = json.toMap()
        )
    }

    /**
     * The `upns` claim (historical UPNs): a JSON array of strings, or the empty list when the
     * claim is absent or misshapen. Falls back rather than throwing, like every optional claim here.
     */
    private fun JSONObject.parseUpns(): List<String> {
        val array = optJSONArray("upns") ?: return emptyList()
        val values = List(array.length()) { index -> array.opt(index) }
        return values.takeIf { list -> list.all { it is String } }
            ?.map { it as String }
            ?: emptyList()
    }

    private fun JSONObject.toMap(): Map<String, Any?> =
        keys().asSequence().associateWith { key -> get(key).toKotlinJsonValue() }

    private fun JSONArray.toList(): List<Any?> =
        List(length()) { index -> get(index).toKotlinJsonValue() }

    private fun Any?.toKotlinJsonValue(): Any? {
        if (this == null || this === JSONObject.NULL) return null
        return when (this) {
            is JSONObject -> toMap()
            is JSONArray -> toList()
            else -> this
        }
    }

    internal companion object {
        private const val HTTP_NO_CONTENT = 204

        /** CAS defaults, applied when the response omits the lifetime. */
        private const val DEFAULT_PAR_EXPIRES_IN_SECONDS = 300
        private const val DEFAULT_TOKEN_EXPIRES_IN_SECONDS = 3600

        private const val REDACTED = "[REDACTED]"

        // Three base64url segments joined by dots: an id_token, access_token or JWT-shaped code.
        private val JWT_SHAPED = Regex("""[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}""")

        // Anything else long and opaque: an opaque access token, a refresh token, a code_verifier.
        // 32 is above any OAuth error code or human wording and below every credential we send.
        private val LONG_BASE64URL_RUN = Regex("""[A-Za-z0-9_-]{32,}""")
        private val CLIENT_ERRORS = 400..499

        // One shared connection pool + dispatcher across all CasClients.
        private val sharedHttpClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                // Every request carries a credential; a 307/308 to an http:// or attacker-chosen
                // host would re-send it there, so a redirect is a hard failure instead.
                .followRedirects(false)
                .followSslRedirects(false)
                .build()
        }

        val production: (String, KrdpassEnvironment) -> CasClient =
            { clientId, environment -> CasClient(clientId, environment, sharedHttpClient) }

        /** The one injection seam: a test points this at a local server and restores [production] after. */
        @Volatile
        var forConfig: (String, KrdpassEnvironment) -> CasClient = production
    }
}

internal data class ParResponse(
    val requestUri: String,
    val expiresIn: Int
)

/**
 * CAS communication failure. Translated into the public [KrdpassError] model at the SDK boundary,
 * so KrdpassError is the only error type thrown from a public entry point.
 */
internal class CasException(
    message: String,
    val statusCode: Int? = null,
    cause: Throwable? = null
) : Exception(message, cause) {

    /**
     * A 5xx, 408 or 429 is transient; a 4xx or an unparseable response is permanent. The single
     * home for that split: the retry loop and the [KrdpassError] translation both read it.
     */
    val isRetryable: Boolean
        get() = statusCode?.let { it >= HTTP_SERVER_ERROR || it == HTTP_REQUEST_TIMEOUT || it == HTTP_TOO_MANY_REQUESTS } ?: false

    private companion object {
        private const val HTTP_SERVER_ERROR = 500
        private const val HTTP_REQUEST_TIMEOUT = 408
        private const val HTTP_TOO_MANY_REQUESTS = 429
    }
}
