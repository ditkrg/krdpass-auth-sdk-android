package krd.pass.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Date

/**
 * Security-critical coverage for the client-only id_token trust path: RS256 signature (JWKS),
 * issuer, audience, expiry, and the nonce replay binding. These drive the entire [KrdpassAuth.signIn]
 * trust decision, so every accept/reject branch, including the classic JWT attacks (tampered
 * signature, wrong signing key, alg:none/unsigned), is asserted here against an in-memory JWKSet
 * (no network, no device).
 */
class JwtVerificationTest {

    private val issuer = "https://auth.dev.krd"
    private val audience = "citizen-demo-app-client"

    private val signingKey: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()
    private val jwkSource: JWKSource<SecurityContext> =
        ImmutableJWKSet(JWKSet(signingKey.toPublicJWK()))

    // --- verifyJwt: signature + iss + aud + exp ------------------------------------------------

    @Test
    fun `a correctly signed token with matching iss aud and a future exp is accepted`() {
        val token = mint(signingKey)
        val claims = TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
        assertEquals("user-123", claims["sub"])
        assertEquals(issuer, claims["iss"])
    }

    @Test
    fun `a token signed by a different key (same kid) is rejected`() {
        // Forged: same kid so the verifier selects the published key, but the signature was made
        // with a key the IdP never published.
        val attackerKey = RSAKeyGenerator(2048).keyID(KID).generate()
        assertRejected(mint(attackerKey))
    }

    @Test
    fun `a token whose signature bytes are tampered is rejected`() {
        val token = mint(signingKey)
        val parts = token.split(".")
        // Flip the FIRST character of the signature segment: it encodes the high bits of the
        // leading signature byte, so this reliably alters the signature (unlike the trailing
        // base64url char, whose low bits are padding and decode to the same bytes).
        val sig = parts[2]
        val tamperedChar = if (sig.first() == 'A') 'B' else 'A'
        val tampered = "${parts[0]}.${parts[1]}.$tamperedChar${sig.drop(1)}"
        assertRejected(tampered)
    }

    @Test
    fun `an unsigned alg-none token is rejected`() {
        val claims = JWTClaimsSet.Builder()
            .subject("user-123").issuer(issuer).audience(audience)
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
            .build()
        assertRejected(PlainJWT(claims).serialize())
    }

    @Test
    fun `a token with the wrong issuer is rejected`() {
        // assertClaimRejected proves the rejection came from claim verification, not an
        // incidental signature/other failure, so it cannot mask a weakened iss check.
        assertClaimRejected(mint(signingKey, issuer = "https://evil.example.com"))
    }

    @Test
    fun `a token with the wrong audience is rejected`() {
        assertClaimRejected(mint(signingKey, audience = "some-other-client"))
    }

    @Test
    fun `an expired token is rejected`() {
        assertClaimRejected(mint(signingKey, expiresInSeconds = -3600))
    }

    @Test
    fun `a token without an exp claim is rejected`() {
        assertClaimRejected(mint(signingKey, expiresInSeconds = null))
    }

    @Test
    fun `a token expired within the clock-skew tolerance is still accepted`() {
        // exp 30s in the past, well inside the 60s skew window -> must NOT be rejected.
        // Locks the skew arithmetic so a future tightening can't start rejecting borderline tokens.
        val token = mint(signingKey, expiresInSeconds = -30)
        val claims = TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
        assertEquals("user-123", claims["sub"])
    }

    // --- validateIdTokenWithSource: the above + nonce replay binding ---------------------------

    @Test
    fun `validateIdToken accepts a fully valid token whose nonce matches`() {
        val token = mint(signingKey, nonce = "nonce-123")
        // Should not throw.
        TokenVerifier.validateIdTokenWithSource(token, jwkSource, issuer, audience, "nonce-123")
    }

    @Test
    fun `validateIdToken rejects a token whose nonce does not match (replay)`() {
        val token = mint(signingKey, nonce = "attacker-nonce")
        assertAuthFailed("nonce") {
            TokenVerifier.validateIdTokenWithSource(token, jwkSource, issuer, audience, "expected-nonce")
        }
    }

    @Test
    fun `validateIdToken rejects a token with no nonce when one is expected`() {
        val token = mint(signingKey, nonce = null)
        assertAuthFailed("nonce") {
            TokenVerifier.validateIdTokenWithSource(token, jwkSource, issuer, audience, "expected-nonce")
        }
    }

    @Test
    fun `validateIdToken rejects a null id_token`() {
        assertAuthFailed("id_token") {
            TokenVerifier.validateIdTokenWithSource(null, jwkSource, issuer, audience, "n")
        }
    }

    @Test
    fun `validateIdToken surfaces a signature failure as AuthenticationFailed`() {
        val attackerKey = RSAKeyGenerator(2048).keyID(KID).generate()
        val token = mint(attackerKey, nonce = "nonce-123")
        assertAuthFailed("validation failed") {
            TokenVerifier.validateIdTokenWithSource(token, jwkSource, issuer, audience, "nonce-123")
        }
    }

    // --- helpers -------------------------------------------------------------------------------

    private fun assertRejected(token: String) {
        try {
            TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
            fail("Expected verifyJwt to reject the token but it was accepted")
        } catch (e: Exception) {
            assertNotNull(e)
        }
    }

    /**
     * Asserts the token is rejected specifically by *claim* verification (Nimbus throws
     * [BadJWTException] for iss/aud/exp failures). Pinning the cause means a crafted token can't
     * pass the test by being rejected for an unrelated reason, so a weakened claim check is caught.
     */
    private fun assertClaimRejected(token: String) {
        try {
            TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
            fail("Expected verifyJwt to reject the token on a claim check but it was accepted")
        } catch (e: BadJWTException) {
            assertNotNull(e)
        }
    }

    private fun assertAuthFailed(messageSubstring: String, block: () -> Unit) {
        try {
            block()
            fail("Expected KrdpassError.AuthenticationFailed but nothing was thrown")
        } catch (e: KrdpassError.AuthenticationFailed) {
            assertTrue(
                "Expected message to contain \"$messageSubstring\" but was \"${e.message}\"",
                e.message?.contains(messageSubstring, ignoreCase = true) == true,
            )
        }
    }

    private fun mint(
        key: RSAKey,
        issuer: String? = this.issuer,
        audience: String? = this.audience,
        expiresInSeconds: Long? = 3600,
        nonce: String? = null,
    ): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder().apply {
            subject("user-123")
            issuer?.let { issuer(it) }
            audience?.let { audience(it) }
            expiresInSeconds?.let { expirationTime(Date(now + it * 1000)) }
            issueTime(Date(now))
            nonce?.let { claim("nonce", it) }
        }.build()
        val signed = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims)
        signed.sign(RSASSASigner(key))
        return signed.serialize()
    }

    companion object {
        private const val KID = "test-key"
    }
}
