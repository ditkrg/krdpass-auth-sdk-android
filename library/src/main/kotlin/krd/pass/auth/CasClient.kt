package krd.pass.auth

import kotlinx.coroutines.delay
import okhttp3.Credentials
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
 */
class CasClient(
    private val clientId: String,
    private val environment: KrdpassEnvironment,
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()
) {

    // Constructor for testing with custom base URL
    constructor(
        clientId: String,
        baseUrl: String,
        httpClient: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    ) : this(clientId, KrdpassEnvironment.Production, httpClient) {
        // For testing, we'll override the URLs
        this.testBaseUrl = baseUrl
    }

    private var testBaseUrl: String? = null

    /**
     * Execute a function with exponential backoff retry logic using coroutines.
     */
    @Throws(Exception::class)
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
        val url = testBaseUrl?.let { "$it/connect/par" } ?: environment.parEndpoint

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

        val request = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()

        return retry {
            httpClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()

                if (!response.isSuccessful) {
                    throw CasException(
                        message = "PAR request failed",
                        statusCode = response.code
                    )
                }

                val json = JSONObject(responseBody ?: "{}")
                if (!json.has("request_uri")) {
                    throw CasException("Invalid PAR response: missing request_uri")
                }
                val requestUri = json.getString("request_uri")
                if (requestUri.isNullOrBlank()) {
                    throw CasException("Invalid PAR response: empty request_uri")
                }
                val expiresIn = if (json.has("expires_in")) json.getInt("expires_in") else 300

                ParResponse(requestUri, expiresIn)
            }
        }
    }

    /**
     * Exchange an authorization code for tokens.
     *
     * Returns a [KrdpassTokenResult] containing access and ID tokens.
     */
    @Throws(CasException::class)
    suspend fun exchangeCodeForTokens(
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

        val request = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()

        // An authorization code is single-use: never retry the exchange, or a
        // transient 5xx/network blip after the server already consumed the code
        // turns into a confusing invalid_grant on replay. (maxAttempts = 1)
        return retry(maxAttempts = 1) {
            httpClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()

                if (!response.isSuccessful) {
                    throw CasException(
                        message = "Token exchange failed",
                        statusCode = response.code
                    )
                }

                val json = JSONObject(responseBody ?: "{}")

                if (!json.has("access_token")) {
                    throw CasException("Invalid token response: missing access_token")
                }

                val accessToken = json.getString("access_token")
                if (accessToken.isNullOrBlank()) {
                    throw CasException("Invalid token response: empty access_token")
                }

                KrdpassTokenResult(
                    accessToken = accessToken,
                    idToken = if (json.has("id_token")) json.getString("id_token") else null,
                    tokenType = if (json.has("token_type")) json.getString("token_type") else "Bearer",
                    expiresIn = if (json.has("expires_in")) json.getInt("expires_in") else 3600,
                    refreshToken = if (json.has("refresh_token")) json.getString("refresh_token") else null,
                    scope = if (json.has("scope")) json.getString("scope") else null
                )
            }
        }
    }

    /**
     * Get user info from CAS using an access token.
     *
     * Returns a [KrdpassUserInfo] object containing user claims.
     */
    @Throws(CasException::class)
    suspend fun getUserInfo(accessToken: String): KrdpassUserInfo {
        require(accessToken.isNotBlank()) { "accessToken cannot be blank" }
        val url = environment.userInfoEndpoint

        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $accessToken")
            .get()
            .build()

        return retry {
            httpClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()

                if (!response.isSuccessful) {
                    throw CasException(
                        message = "UserInfo request failed",
                        statusCode = response.code
                    )
                }

                val json = JSONObject(responseBody ?: "{}")
                parseUserInfo(json)
            }
        }
    }

    /**
     * Refresh tokens using a refresh token.
     */
    @Throws(CasException::class)
    suspend fun refreshTokens(
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

        val request = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()
            
        log("DEBUG", "Refreshing tokens at: $url")
        log("DEBUG", "Params: grant_type=refresh_token, client_id=$clientId, refresh_token=[REDACTED]")

        return retry {
            httpClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()

                if (!response.isSuccessful) {
                    val message = try {
                        val errorJson = JSONObject(responseBody ?: "{}")
                        val error = errorJson.optString("error", "Token refresh failed")
                        val desc = errorJson.optString("error_description", "")
                        if (desc.isNotBlank()) "$error: $desc" else error
                    } catch (e: Exception) {
                        "Token refresh failed: $responseBody"
                    }
                    throw CasException(
                        message = message,
                        statusCode = response.code
                    )
                }

                val json = JSONObject(responseBody ?: "{}")
                if (!json.has("access_token")) {
                    throw CasException("Invalid token response: missing access_token")
                }

                val accessToken = json.getString("access_token")
                if (accessToken.isNullOrBlank()) {
                    throw CasException("Invalid token response: empty access_token")
                }

                KrdpassTokenResult(
                    accessToken = accessToken,
                    idToken = if (json.has("id_token")) json.getString("id_token") else null,
                    tokenType = if (json.has("token_type")) json.getString("token_type") else "Bearer",
                    expiresIn = if (json.has("expires_in")) json.getInt("expires_in") else 3600,
                    refreshToken = if (json.has("refresh_token")) json.getString("refresh_token") else null,
                    scope = if (json.has("scope")) json.getString("scope") else null
                )
            }
        }
    }

    /**
     * Revoke an access or refresh token.
     */
    @Throws(CasException::class)
    suspend fun revokeToken(
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

        val request = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()
            
        log("DEBUG", "Revoking token at: $url")
        log("DEBUG", "Params: client_id=$clientId, token=[REDACTED], hint=$tokenTypeHint")

        retry {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful && response.code != 204) {
                    val responseBody = response.body?.string()
                    val message = try {
                        val errorJson = JSONObject(responseBody ?: "{}")
                        val error = errorJson.optString("error", "Token revocation failed")
                        val desc = errorJson.optString("error_description", "")
                        if (desc.isNotBlank()) "$error: $desc" else error
                    } catch (e: Exception) {
                        "Token revocation failed: $responseBody"
                    }
                    throw CasException(
                        message = message,
                        statusCode = response.code
                    )
                }
            }
        }
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

    private fun JSONObject.toMap(): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        val keys = keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val value = get(key)
            map[key] = if (value == JSONObject.NULL) null else value
        }
        return map
    }

    /**
     * Verify a JWT using a JWKS URL and validate standard claims.
     */
    @Throws(Exception::class)
    fun verifyToken(
        token: String,
        issuer: String? = null,
        audience: String? = null,
        clockSkewSeconds: Long = 60
    ): Map<String, Any?> {
        require(token.isNotBlank()) { "token cannot be blank" }
        // Use environment from CasClient property
        
        val jwkSource = com.nimbusds.jose.jwk.source.JWKSourceBuilder.create<com.nimbusds.jose.proc.SecurityContext>(java.net.URL(environment.jwksEndpoint))
            .retrying(true) // Enable retries
            .build()
            
        val keySelector = com.nimbusds.jose.proc.JWSVerificationKeySelector(com.nimbusds.jose.JWSAlgorithm.Family.RSA, jwkSource)
        val jwtProcessor = com.nimbusds.jwt.proc.DefaultJWTProcessor<com.nimbusds.jose.proc.SecurityContext>().apply {
            jwsKeySelector = keySelector
        }

        val requiredClaims = com.nimbusds.jwt.JWTClaimsSet.Builder().apply {
            if (!issuer.isNullOrBlank()) issuer(issuer)
            if (!audience.isNullOrBlank()) audience(audience)
        }.build()

        // Only `exp` is mandatory (a token must expire). `nbf`/`iat` are optional per OIDC and
        // are still validated *if present* below; requiring them rejects otherwise-valid id_tokens.
        val requiredClaimNames = mutableSetOf("exp").apply {
            if (!issuer.isNullOrBlank()) add("iss")
            if (!audience.isNullOrBlank()) add("aud")
        }

        val verifier: com.nimbusds.jwt.proc.JWTClaimsSetVerifier<com.nimbusds.jose.proc.SecurityContext> =
            com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier(requiredClaims, requiredClaimNames)
        jwtProcessor.jwtClaimsSetVerifier = verifier

        // Process with clock skew tolerance
        val claims = jwtProcessor.process(token, null)
        
        // Manual clock skew validation
        val now = System.currentTimeMillis() / 1000
        claims.expirationTime?.let { exp ->
            if (now - clockSkewSeconds > exp.time / 1000) {
                throw Exception("Token expired")
            }
        }
        claims.notBeforeTime?.let { nbf ->
            if (now + clockSkewSeconds < nbf.time / 1000) {
                throw Exception("Token not yet valid")
            }
        }
        
        return claims.claims
    }
}

/**
 * Response from a PAR (Pushed Authorization Request) call.
 */
data class ParResponse(
    val requestUri: String,
    val expiresIn: Int
)

/**
 * Exception thrown when CAS communication fails.
 */
class CasException(
    message: String,
    val statusCode: Int? = null,
    cause: Throwable? = null
) : Exception(message, cause) {

    override fun toString(): String {
        val statusPart = statusCode?.let { " (status: $it)" } ?: ""
        return "CasException: $message$statusPart"
    }
}
