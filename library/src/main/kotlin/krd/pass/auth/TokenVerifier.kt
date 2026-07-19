package krd.pass.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import java.net.URL

/**
 * OIDC/JWT verification + JWKS caching, separated from [KrdpassAuth] so the network-fetching key
 * source and the pure claim checks each have one home, and the security-critical verification math
 * exists exactly once (shared by [KrdpassAuth] and [CasClient]).
 */
internal object TokenVerifier {

    /** JWKS cache time-to-live: refetch the verification keys at most once an hour. */
    private const val JWKS_CACHE_TTL_MILLIS = 60L * 60 * 1000

    // JWKS cache: a single @Volatile holder so the (source, expiry) pair is read/swapped
    // atomically from IO-dispatched coroutines, no torn check-then-act under concurrent use.
    private data class JwksCache(val source: JWKSource<SecurityContext>, val expiresAt: Long)
    @Volatile
    private var jwksCache: JwksCache? = null

    /** Drop the cached JWKS: call when the configured environment changes. */
    fun clearCache() {
        jwksCache = null
    }

    /** Fetch this environment's JWKS and verify [token] against it. */
    fun verifyToken(
        jwksUrl: String,
        token: String,
        issuer: String?,
        audience: String?,
        clockSkewSeconds: Long,
    ): Map<String, Any?> = verifyJwt(token, getJwkSource(jwksUrl), issuer, audience, clockSkewSeconds)

    /**
     * Full client-only id_token trust decision: signature + iss + aud + exp via [verifyJwt], then
     * the nonce replay binding. Fetches the JWKS for [environment].
     *
     * @throws KrdpassError.AuthenticationFailed if any check fails.
     */
    fun validateIdToken(
        environment: KrdpassEnvironment,
        audience: String,
        idToken: String?,
        expectedNonce: String,
    ) {
        validateIdTokenWithSource(
            idToken = idToken,
            jwkSource = getJwkSource(environment.jwksEndpoint),
            issuer = environment.authServerUrl,
            audience = audience,
            expectedNonce = expectedNonce,
        )
    }

    /**
     * Like [validateIdToken] but against a supplied [jwkSource], so it is unit-testable with an
     * in-memory JWKSet (no network).
     *
     * @throws KrdpassError.AuthenticationFailed if any check fails.
     */
    fun validateIdTokenWithSource(
        idToken: String?,
        jwkSource: JWKSource<SecurityContext>,
        issuer: String,
        audience: String,
        expectedNonce: String,
        clockSkewSeconds: Long = 60,
    ) {
        // Structured codes match the iOS SDK (invalid_id_token / nonce_mismatch) so bridges can
        // surface them typed instead of a generic authentication_failed.
        if (idToken.isNullOrBlank()) {
            throw KrdpassError.AuthenticationFailed(
                KrdpassMessages.MISSING_ID_TOKEN, code = "invalid_id_token")
        }
        val claims = try {
            verifyJwt(idToken, jwkSource, issuer, audience, clockSkewSeconds)
        } catch (e: Exception) {
            throw KrdpassError.AuthenticationFailed(
                "ID token validation failed: ${e.message}", code = "invalid_id_token")
        }
        val returnedNonce = claims["nonce"] as? String
        if (returnedNonce.isNullOrBlank() || returnedNonce != expectedNonce) {
            throw KrdpassError.AuthenticationFailed(
                KrdpassMessages.NONCE_MISMATCH, code = "nonce_mismatch")
        }
    }

    /**
     * Stateless RS256 JWT verification against a supplied [source]: signature, required `exp`, and
     * (when supplied) `iss`/`aud`, plus clock-skew-tolerant exp/nbf/iat checks. Separated from
     * [getJwkSource] so it is unit-testable with an in-memory JWKSet (no network).
     */
    fun verifyJwt(
        token: String,
        source: JWKSource<SecurityContext>,
        issuer: String?,
        audience: String?,
        clockSkewSeconds: Long,
    ): Map<String, Any?> {
        val selector = JWSVerificationKeySelector(JWSAlgorithm.Family.RSA, source)
        val processor = DefaultJWTProcessor<SecurityContext>().apply { jwsKeySelector = selector }

        val requiredClaims = JWTClaimsSet.Builder().apply {
            if (!issuer.isNullOrBlank()) issuer(issuer)
            if (!audience.isNullOrBlank()) audience(audience)
        }.build()

        // Always require exp so a token with no expiry can never be accepted as non-expiring.
        val requiredClaimNames = mutableSetOf("exp").apply {
            if (!issuer.isNullOrBlank()) add("iss")
            if (!audience.isNullOrBlank()) add("aud")
        }

        val verifier: JWTClaimsSetVerifier<SecurityContext> =
            DefaultJWTClaimsVerifier(requiredClaims, requiredClaimNames)
        processor.jwtClaimsSetVerifier = verifier

        val claims = processor.process(token, null)

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
        claims.issueTime?.let { iat ->
            if (now + clockSkewSeconds < iat.time / 1000) {
                throw Exception("Token used before issued")
            }
        }

        return claims.claims
    }

    /**
     * Decode a JWT's claims **without verifying its signature**.
     *
     * SECURITY: the returned claims are NOT authenticated and MUST NOT drive any trust or
     * authorization decision. Verify first; this is only for cosmetic display of an already-verified
     * token.
     *
     * @throws IllegalArgumentException if [token] is not a parseable JWT.
     */
    fun decodeTokenUnverified(token: String): Map<String, Any?> {
        return try {
            JWTParser.parse(token).jwtClaimsSet.claims
        } catch (e: Exception) {
            throw IllegalArgumentException("Not a valid JWT", e)
        }
    }

    private fun getJwkSource(url: String): JWKSource<SecurityContext> {
        val now = System.currentTimeMillis()
        // Read the volatile holder once: branch on the local, never re-deref under a null race.
        jwksCache?.let { if (now < it.expiresAt) return it.source }
        val newSource = JWKSourceBuilder.create<SecurityContext>(URL(url)).retrying(true).build()
        jwksCache = JwksCache(newSource, now + JWKS_CACHE_TTL_MILLIS)
        return newSource
    }
}
