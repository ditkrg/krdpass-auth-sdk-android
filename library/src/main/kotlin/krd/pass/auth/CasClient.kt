package krd.pass.auth

import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Internal client for communicating directly with CAS.
 *
 * Used by [KrdpassAuth.signIn] for client-only authentication mode.
 * This client handles PAR (Pushed Authorization Request) and token exchange.
 *
 * Public on purpose: the React Native bridge (krdpass-auth-react-native android module) uses
 * this directly for stateless per-call token ops, so it must stay public: do not internalize.
 */
public class CasClient(
    private val clientId: String,
    private val environment: KrdpassEnvironment,
    private val httpClient: OkHttpClient = sharedHttpClient
) {

    // Constructor for testing with custom base URL
    internal constructor(
        clientId: String,
        baseUrl: String,
        httpClient: OkHttpClient = sharedHttpClient
    ) : this(clientId, KrdpassEnvironment.Production, httpClient) {
        this.testBaseUrl = baseUrl
    }

    private var testBaseUrl: String? = null

    /** Tolerant decoder: ignore extra claims/fields CAS may add over time. */
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Send [request] with retry, and on a non-success response (outside [okStatusCodes]) throw a
     * [CasException] labelled "[label] failed (code): <parsed error>". On success, [parse] decodes
     * the body (blank bodies are fed as "{}" so a decoder never chokes on an empty 2xx). This is the
     * single request/response funnel for every CAS endpoint below.
     */
    private suspend fun <T> execute(
        request: Request,
        label: String,
        maxAttempts: Int = 3,
        okStatusCodes: Set<Int> = emptySet(),
        parse: (body: String) -> T,
    ): T = retry(maxAttempts) {
        httpClient.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful && response.code !in okStatusCodes) {
                log("ERROR", "$label failed (${response.code}): $body")
                throw CasException("$label failed (${response.code}): ${parseCasError(body)}", response.code)
            }
            parse(body.ifBlank { "{}" })
        }
    }

    /**
     * Execute a function with linear backoff retry logic using coroutines.
     */
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
            } catch (e: Exception) {
                if (attempt >= maxAttempts) throw e

                // Don't retry on non-transient OAuth errors
                if (e is CasException) {
                    val status = e.statusCode
                    if (status == null) throw e
                    if (status in 400..499 && status != 408 && status != 429) {
                        throw e
                    }
                }

                log("DEBUG", "Request failed (attempt $attempt/$maxAttempts). Retrying in ${initialDelayMillis * attempt}ms...")
                delay(initialDelayMillis * attempt)
            }
        }
    }

    /**
     * Push an authorization request to CAS.
     *
     * Returns a [ParResponse] containing the request_uri to use for authorization.
     */
    @Throws(CasException::class)
    public suspend fun pushAuthorizationRequest(
        codeChallenge: String,
        redirectUri: String,
        scopes: List<String>,
        state: String? = null,
        nonce: String? = null
    ): ParResponse {
        require(codeChallenge.isNotBlank()) { "codeChallenge cannot be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri cannot be blank" }
        require(scopes.isNotEmpty()) { "scopes cannot be empty" }
        val url = testBaseUrl?.let { "$it/connect/par" } ?: environment.parEndpoint
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
            val dto = json.decodeFromString<ParResponseDto>(body)
            if (dto.requestUri.isNullOrBlank()) {
                throw CasException("Invalid PAR response: missing or empty request_uri")
            }
            ParResponse(dto.requestUri, dto.expiresIn)
        }
    }

    /**
     * Exchange an authorization code for tokens.
     *
     * Returns a [KrdpassTokenResult] containing access and ID tokens.
     */
    @Throws(CasException::class)
    public suspend fun exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        redirectUri: String
    ): KrdpassTokenResult {
        require(code.isNotBlank()) { "code cannot be blank" }
        require(codeVerifier.isNotBlank()) { "codeVerifier cannot be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri cannot be blank" }
        val url = testBaseUrl?.let { "$it/connect/token" } ?: environment.tokenEndpoint

        val requestBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("client_id", clientId)
            .add("redirect_uri", redirectUri)
            .add("code", code)
            .add("code_verifier", codeVerifier)
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()

        // An authorization code is single-use: never retry the exchange, or a transient 5xx/network
        // blip after the server already consumed the code turns into a confusing invalid_grant on
        // replay. (maxAttempts = 1)
        return execute(request, "Token exchange", maxAttempts = 1) { body ->
            json.decodeFromString<TokenResponseDto>(body).toTokenResult()
        }
    }

    /**
     * Get user info from CAS using an access token.
     *
     * Returns a [KrdpassUserInfo] object containing user claims.
     */
    @Throws(CasException::class)
    public suspend fun getUserInfo(accessToken: String): KrdpassUserInfo {
        require(accessToken.isNotBlank()) { "accessToken cannot be blank" }

        val request = Request.Builder()
            .url(environment.userInfoEndpoint)
            .addHeader("Authorization", "Bearer $accessToken")
            .get()
            .build()

        // UserInfo carries dynamic, open-ended claims (and a `raw` passthrough map), so it is parsed
        // with org.json rather than a fixed DTO.
        return execute(request, "UserInfo request") { body -> parseUserInfo(JSONObject(body)) }
    }

    /**
     * Refresh tokens using a refresh token.
     */
    @Throws(CasException::class)
    public suspend fun refreshTokens(
        refreshToken: String,
        scope: String? = null
    ): KrdpassTokenResult {
        require(refreshToken.isNotBlank()) { "refreshToken cannot be blank" }
        val url = testBaseUrl?.let { "$it/connect/token" } ?: environment.tokenEndpoint

        val requestBody = FormBody.Builder()
            .add("client_id", clientId)
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .apply { if (!scope.isNullOrBlank()) add("scope", scope) }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()
        log("DEBUG", "Refreshing tokens at: $url (client_id=$clientId, refresh_token=[REDACTED])")

        // Refresh tokens can be rotated (single-use) by the CAS: a retry after a
        // timeout/5xx-that-committed would replay the consumed token, and reuse detection can
        // revoke the whole token family. Same rationale as the code exchange. (maxAttempts = 1)
        return execute(request, "Token refresh", maxAttempts = 1) { body ->
            json.decodeFromString<TokenResponseDto>(body).toTokenResult()
        }
    }

    /**
     * Revoke an access or refresh token.
     */
    @Throws(CasException::class)
    public suspend fun revokeToken(
        token: String,
        tokenTypeHint: String? = null
    ) {
        require(token.isNotBlank()) { "token cannot be blank" }
        val url = testBaseUrl?.let { "$it/connect/revocation" } ?: environment.revocationEndpoint

        val requestBody = FormBody.Builder()
            .add("client_id", clientId)
            .add("token", token)
            .apply { if (!tokenTypeHint.isNullOrBlank()) add("token_type_hint", tokenTypeHint) }
            .build()

        val request = Request.Builder().url(url).post(requestBody).build()
        log("DEBUG", "Revoking token at: $url (client_id=$clientId, token=[REDACTED], hint=$tokenTypeHint)")

        // RFC 7009: a successful revocation returns 200; some servers return 204 (no content).
        execute(request, "Token revocation", okStatusCodes = setOf(204)) { }
    }

    /** Best-effort OAuth error string from a response body; falls back to the raw body. */
    private fun parseCasError(body: String): String {
        if (body.isBlank()) return body
        return try {
            val err = json.decodeFromString<CasErrorDto>(body)
            when {
                !err.error.isNullOrBlank() && !err.errorDescription.isNullOrBlank() -> "${err.error}: ${err.errorDescription}"
                !err.error.isNullOrBlank() -> err.error
                else -> body
            }
        } catch (_: Exception) {
            body
        }
    }

    /** Maps a decoded token response to the public result, failing closed on a missing access_token. */
    private fun TokenResponseDto.toTokenResult(): KrdpassTokenResult {
        if (accessToken.isNullOrBlank()) {
            throw CasException("Invalid token response: missing or empty access_token")
        }
        return KrdpassTokenResult(
            accessToken = accessToken,
            idToken = idToken,
            tokenType = tokenType,
            expiresIn = expiresIn,
            refreshToken = refreshToken,
            scope = scope
        )
    }

    private fun parseUserInfo(json: JSONObject): KrdpassUserInfo {
        return KrdpassUserInfo(
            sub = json.getString("sub"),
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
            did = json.optString("did").takeIf { it.isNotBlank() },
            raw = json.toMap()
        )
    }

    private fun JSONObject.toMap(): Map<String, Any?> =
        keys().asSequence().associateWith { k -> get(k).takeUnless { it == JSONObject.NULL } }

    /**
     * Verify a JWT against this environment's JWKS and validate standard claims. Delegates to the
     * canonical [TokenVerifier.verifyToken] (its hourly-cached key source + single verification impl).
     *
     * The first call performs blocking network I/O (JWKS fetch), so call this off the main thread.
     */
    @Throws(Exception::class)
    public fun verifyToken(
        token: String,
        issuer: String? = null,
        audience: String? = null,
        clockSkewSeconds: Long = 60
    ): Map<String, Any?> {
        require(token.isNotBlank()) { "token cannot be blank" }
        return TokenVerifier.verifyToken(environment.jwksEndpoint, token, issuer, audience, clockSkewSeconds)
    }

    private companion object {
        // OkHttp is designed to be shared: one connection pool + dispatcher across all CasClients.
        private val sharedHttpClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build()
        }
    }
}

/**
 * Response from a PAR (Pushed Authorization Request) call.
 */
public data class ParResponse(
    val requestUri: String,
    val expiresIn: Int
)

/**
 * Exception thrown when CAS communication fails.
 */
public class CasException(
    message: String,
    public val statusCode: Int? = null,
    cause: Throwable? = null
) : Exception(message, cause)
