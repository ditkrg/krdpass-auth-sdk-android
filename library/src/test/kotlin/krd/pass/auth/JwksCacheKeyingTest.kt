package krd.pass.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.Assert.fail
import java.util.Date

/**
 * The JWKS cache must be keyed by JWKS URL: a cache that ignores the URL would accept a token
 * signed by the Development key as a Production token for the lifetime of the entry. Fetches real
 * JWKS documents over loopback so the assertion is about the shipped caching path.
 */
class JwksCacheKeyingTest {

    private val productionKey: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()
    private val developmentKey: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()

    private lateinit var production: MockWebServer
    private lateinit var development: MockWebServer

    @Before
    fun setUp() {
        TokenVerifier.clearCache()
        production = serverPublishing(productionKey)
        development = serverPublishing(developmentKey)
    }

    @After
    fun tearDown() {
        production.close()
        development.close()
        TokenVerifier.clearCache()
    }

    @Test
    fun `a development-signed token is rejected against the production jwks url`() {
        val forged = mint(developmentKey)

        // Warm the cache against Development, then verify the same token against Production's
        // JWKS URL: Production never published this key, so only a signature failure is correct.
        TokenVerifier.verifyToken(development.jwksUrl(), forged, ISSUER, AUDIENCE, SKEW)

        try {
            TokenVerifier.verifyToken(production.jwksUrl(), forged, ISSUER, AUDIENCE, SKEW)
            fail("a Development-signed token verified against the Production JWKS URL")
        } catch (expected: Exception) {
        }
    }

    @Test
    fun `each environment's jwks url is fetched on first use`() {
        val productionToken = mint(productionKey)
        val developmentToken = mint(developmentKey)

        TokenVerifier.verifyToken(development.jwksUrl(), developmentToken, ISSUER, AUDIENCE, SKEW)
        TokenVerifier.verifyToken(production.jwksUrl(), productionToken, ISSUER, AUDIENCE, SKEW)

        assertEquals("development JWKS should be fetched once", 1, development.requestCount)
        assertEquals("production JWKS should be fetched once", 1, production.requestCount)
    }

    @Test
    fun `a repeat verification against the same url does not refetch`() {
        val token = mint(productionKey)

        TokenVerifier.verifyToken(production.jwksUrl(), token, ISSUER, AUDIENCE, SKEW)
        TokenVerifier.verifyToken(production.jwksUrl(), token, ISSUER, AUDIENCE, SKEW)

        assertEquals("second verification should hit the cache", 1, production.requestCount)
    }

    private fun serverPublishing(key: RSAKey): MockWebServer {
        val body = JWKSet(key.toPublicJWK()).toString()
        return MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    MockResponse.Builder()
                        .setHeader("Content-Type", "application/json")
                        .body(body)
                        .build()
            }
            start()
        }
    }

    private fun MockWebServer.jwksUrl(): String = url("/.well-known/jwks").toString()

    private fun mint(key: RSAKey): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-123")
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .expirationTime(Date(System.currentTimeMillis() + 600_000))
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims).apply {
            sign(RSASSASigner(key))
        }.serialize()
    }

    private companion object {
        const val KID = "test-key"
        const val ISSUER = "https://auth.dev.krd"
        const val AUDIENCE = "test-client-id"
        const val SKEW = 60L
    }
}
