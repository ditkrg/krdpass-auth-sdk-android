package krd.pass.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Date

/**
 * refreshTokens must verify a returned `id_token`, the same way the iOS SDK does. Exercises the
 * shipped path ([KrdpassAuth.verifyRefreshedIdTokenIfPresent]) against a loopback JWKS server.
 */
class RefreshTokenVerificationTest {

    private val signingKey: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()
    private lateinit var jwks: MockWebServer

    @Before
    fun setUp() {
        TokenVerifier.clearCache()
        jwks = MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    MockResponse.Builder()
                        .setHeader("Content-Type", "application/json")
                        .body(JWKSet(signingKey.toPublicJWK()).toString())
                        .build()
            }
            start()
        }
    }

    @After
    fun tearDown() {
        jwks.close()
        TokenVerifier.clearCache()
    }

    @Test
    fun `a present valid id_token is verified against the JWKS endpoint`() = runBlocking {
        val token = mint(signingKey)

        // Should not throw.
        KrdpassAuth.verifyRefreshedIdTokenIfPresent(token, jwks.jwksUrl(), ISSUER, AUDIENCE)

        assertEquals("the id_token must actually be checked against the JWKS", 1, jwks.requestCount)
    }

    @Test
    fun `a present but forged id_token fails verification`() = runBlocking {
        val attackerKey = RSAKeyGenerator(2048).keyID(KID).generate()
        val forged = mint(attackerKey)

        try {
            KrdpassAuth.verifyRefreshedIdTokenIfPresent(forged, jwks.jwksUrl(), ISSUER, AUDIENCE)
            fail("a token signed by an unpublished key must not verify")
        } catch (expected: KrdpassError) {
            // A forged refresh id_token must surface as the same public error model verifyToken uses.
        }
    }

    @Test
    fun `a null id_token is not verified and the JWKS is never fetched`() = runBlocking {
        KrdpassAuth.verifyRefreshedIdTokenIfPresent(null, jwks.jwksUrl(), ISSUER, AUDIENCE)

        assertEquals("no id_token means no verification attempt", 0, jwks.requestCount)
    }

    @Test
    fun `a blank id_token is not verified and the JWKS is never fetched`() = runBlocking {
        KrdpassAuth.verifyRefreshedIdTokenIfPresent("", jwks.jwksUrl(), ISSUER, AUDIENCE)

        assertEquals("a blank id_token means no verification attempt", 0, jwks.requestCount)
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
    }
}
