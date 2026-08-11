package krd.pass.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import java.net.URI
import java.text.ParseException
import java.util.concurrent.ConcurrentHashMap

/**
 * A claim this SDK checks itself because Nimbus does not (`iat`, and `azp` when present).
 * Extends [BadJWTException] so every claim-level rejection, Nimbus's and ours, is catchable as one.
 */
internal class InvalidTokenClaimException(message: String) : BadJWTException(message)

/**
 * OIDC/JWT verification + JWKS caching. The security-critical verification math exists exactly
 * once, here.
 */
internal object TokenVerifier {

    /** JWKS cache time-to-live: refetch the verification keys at most once an hour. */
    private const val JWKS_CACHE_TTL_MILLIS = 60L * 60 * 1000

    /** How long a thread waits for another thread's in-progress JWKS refresh before fetching itself. */
    private const val JWKS_REFRESH_TIMEOUT_MILLIS = 15L * 1000

    private const val MILLIS_PER_SECOND = 1000

    /** An unbounded skew would switch off the expiry check entirely. */
    private const val MAX_CLOCK_SKEW_SECONDS = 300L

    // Keyed by JWKS URL, and the key matters: a process verifying against more than one environment
    // must never satisfy a Production verification from a cached Development key set.
    private val jwksSources = ConcurrentHashMap<String, JWKSource<SecurityContext>>()

    /** Drop the cached JWKS: call when the configured environment changes. */
    fun clearCache() {
        jwksSources.clear()
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
     * Full client-only id_token trust decision: signature + iss + aud + exp, then the nonce replay
     * binding. Fetches the JWKS for [environment].
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
     * [validateIdToken] against a supplied [jwkSource], so it is unit-testable with an in-memory
     * JWKSet.
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
        // Structured codes match the iOS SDK (invalid_id_token / nonce_mismatch).
        if (idToken.isNullOrBlank()) {
            throw KrdpassError.AuthenticationFailed(
                KrdpassMessages.MISSING_ID_TOKEN, code = "invalid_id_token")
        }
        // Narrow catches: these three mean "the token is not acceptable". Anything else out of
        // Nimbus is a genuine fault and must surface as itself, not as an invalid token.
        val claims = try {
            verifyJwt(idToken, jwkSource, issuer, audience, clockSkewSeconds)
        } catch (e: BadJOSEException) {
            throw invalidIdToken(e)
        } catch (e: JOSEException) {
            throw invalidIdToken(e)
        } catch (e: ParseException) {
            throw invalidIdToken(e)
        }
        val returnedNonce = claims["nonce"] as? String
        if (returnedNonce.isNullOrBlank() || returnedNonce != expectedNonce) {
            throw KrdpassError.AuthenticationFailed(
                KrdpassMessages.NONCE_MISMATCH, code = "nonce_mismatch")
        }
    }

    private fun invalidIdToken(cause: Exception): KrdpassError.AuthenticationFailed =
        KrdpassError.AuthenticationFailed(
            "ID token validation failed: ${cause.message}", code = "invalid_id_token")

    /**
     * Stateless RS256 JWT verification against a supplied [source]: signature, required `exp`, and
     * (when supplied) `iss`/`aud`, tolerant of at most [MAX_CLOCK_SKEW_SECONDS] of clock skew.
     */
    fun verifyJwt(
        token: String,
        source: JWKSource<SecurityContext>,
        issuer: String?,
        audience: String?,
        clockSkewSeconds: Long,
    ): Map<String, Any?> {
        val skew = clockSkewSeconds.coerceIn(0, MAX_CLOCK_SKEW_SECONDS)
        // RS256 exactly, not Family.RSA: CAS issues RS256 only, and the iOS SDK and reference
        // backend pin RS256 only. A family-wide selector would also accept RS384/512 and PS256/384/512.
        val selector = JWSVerificationKeySelector(JWSAlgorithm.RS256, source)
        val processor = DefaultJWTProcessor<SecurityContext>().apply { jwsKeySelector = selector }

        // aud must equal the client id exactly: stricter than OIDC Core 3.1.3.7, which only
        // requires aud to contain it, so multi-audience tokens are rejected. If CAS ever issues
        // multi-audience id_tokens this line breaks sign-in, in all four SDKs together.
        val requiredClaims = JWTClaimsSet.Builder().apply {
            if (!issuer.isNullOrBlank()) issuer(issuer)
            if (!audience.isNullOrBlank()) audience(audience)
        }.build()

        // Always require exp so a token with no expiry can never be accepted as non-expiring.
        val requiredClaimNames = mutableSetOf("exp").apply {
            if (!issuer.isNullOrBlank()) add("iss")
            if (!audience.isNullOrBlank()) add("aud")
        }

        // The caller's skew must reach Nimbus: unset, it applies its own 60s default to exp and nbf.
        val verifier = DefaultJWTClaimsVerifier<SecurityContext>(requiredClaims, requiredClaimNames)
        verifier.maxClockSkew = skew.toInt()
        processor.jwtClaimsSetVerifier = verifier

        val claims = processor.process(token, null)

        // OIDC Core 3.1.3.7: azp must name this client when present, and must be present when aud
        // carries more than one value. Nimbus checks neither. The multi-audience arm cannot fire
        // while the aud pin above stays exact; kept for whoever relaxes that pin.
        if (!audience.isNullOrBlank()) {
            val azp = claims.claims["azp"] as? String
            if ((azp != null || claims.audience.orEmpty().size > 1) && azp != audience) {
                throw InvalidTokenClaimException("Token azp does not name the expected client")
            }
        }

        // Nimbus checks exp and nbf; it does not check iat, so that one stays here.
        claims.issueTime?.let { iat ->
            val now = System.currentTimeMillis() / MILLIS_PER_SECOND
            if (now + skew < iat.time / MILLIS_PER_SECOND) {
                throw InvalidTokenClaimException("Token used before issued")
            }
        }

        return claims.claims
    }

    /**
     * Decode a JWT's claims **without verifying its signature**. SECURITY: the returned claims are
     * NOT authenticated and MUST NOT drive any trust decision.
     * @throws IllegalArgumentException if [token] is not a parseable JWT.
     */
    fun decodeTokenUnverified(token: String): Map<String, Any?> {
        return try {
            JWTParser.parse(token).jwtClaimsSet.claims
        } catch (e: ParseException) {
            throw IllegalArgumentException("Not a valid JWT", e)
        }
    }

    private fun getJwkSource(url: String): JWKSource<SecurityContext> =
        jwksSources.computeIfAbsent(url) {
            JWKSourceBuilder.create<SecurityContext>(URI.create(it).toURL())
                .cache(JWKS_CACHE_TTL_MILLIS, JWKS_REFRESH_TIMEOUT_MILLIS)
                .retrying(true)
                .build()
        }
}
