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
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Date

/**
 * Security-critical coverage for the client-only id_token trust path: signature, issuer, audience,
 * expiry, and the nonce replay binding, including the classic JWT attacks, asserted against an
 * in-memory JWKSet.
 */
class JwtVerificationTest {

    private val issuer = KrdpassEnvironment.Development.authServerUrl
    private val audience = "test-client-id"

    private val signingKey: RSAKey = RSAKeyGenerator(2048).keyID(KID).generate()
    private val jwkSource: JWKSource<SecurityContext> =
        ImmutableJWKSet(JWKSet(signingKey.toPublicJWK()))

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
        // Flip the first character of the signature segment: unlike the trailing base64url char,
        // whose low bits are padding, this reliably alters the decoded signature bytes.
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
    fun `a token signed with a non-RS256 RSA-family alg is rejected`() {
        // Correctly signed with the published key, but the key selector pins RS256 exactly.
        // A Family.RSA selector would have accepted the RS384 token.
        assertRejected(signWithAlg(JWSAlgorithm.RS384))
        assertRejected(signWithAlg(JWSAlgorithm.PS256))
    }

    @Test
    fun `a token with the wrong issuer is rejected`() {
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
        // Locks the skew arithmetic so a future tightening can't start rejecting borderline tokens.
        val token = mint(signingKey, expiresInSeconds = -30)
        val claims = TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
        assertEquals("user-123", claims["sub"])
    }

    @Test
    fun `a clock skew wider than Nimbus's own default is honoured`() {
        // exp 90s in the past: outside Nimbus's built-in 60s tolerance, inside the caller's 300s.
        // Fails if clockSkewSeconds stops reaching the claims verifier itself.
        val token = mint(signingKey, expiresInSeconds = -90)

        val claims = TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 300)

        assertEquals("user-123", claims["sub"])
        assertClaimRejected(token)
    }

    @Test
    fun `the pinned issuer is the environment's authorization server`() {
        // A token minted by any other issuer, including the other environment's, must fail.
        assertEquals(issuer, KrdpassEnvironment.Development.authServerUrl)
        assertClaimRejected(mint(signingKey, issuer = KrdpassEnvironment.Production.authServerUrl))
    }

    // azp, OIDC Core 3.1.3.7 steps 4 and 5: more than one aud -> azp must be present; azp present
    // -> it must name this client. Absent azp at a single aud is the normal shape CAS issues.

    @Test
    fun `single-audience with a matching azp is accepted`() {
        val claims = TokenVerifier.verifyJwt(mintWithAzp(audience), jwkSource, issuer, audience, 60)
        assertEquals(audience, claims["azp"])
    }

    @Test
    fun `single-audience with a wrong azp is rejected`() {
        // Correctly signed and addressed to us, but issued for someone else: only azp catches it.
        assertClaimRejected(mintWithAzp("other-client"))
    }

    @Test
    fun `single-audience with no azp is accepted`() {
        // azp is optional at a single aud, and CAS omits it: requiring it would reject every
        // id_token in production.
        val claims = TokenVerifier.verifyJwt(mint(signingKey), jwkSource, issuer, audience, 60)
        assertEquals("user-123", claims["sub"])
    }

    @Test
    fun `multi-audience is rejected by the aud pin before azp is ever consulted`() {
        // The exact-match aud pin rejects every multi-audience shape, including the one OIDC Core
        // 3.1.3.7 says to accept (multi-aud with a matching azp): stricter than the spec's
        // containment check, for a token shape CAS does not issue. This test is the tripwire for
        // whoever relaxes that pin.
        val both = listOf(audience, "other-client")
        assertClaimRejected(mintWithAzp(audience, audiences = both))
        assertClaimRejected(mintWithAzp("other-client", audiences = both))
        assertClaimRejected(mintWithAzp(null, audiences = both))
    }

    @Test
    fun `a bad azp surfaces from the signIn path as invalid_id_token`() {
        val token = mintWithAzp("other-client", nonce = "nonce-123")
        try {
            TokenVerifier.validateIdTokenWithSource(token, jwkSource, issuer, audience, "nonce-123")
            fail("Expected KrdpassError.AuthenticationFailed but nothing was thrown")
        } catch (e: KrdpassError.AuthenticationFailed) {
            assertEquals("invalid_id_token", e.code)
        }
    }

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

    private fun assertRejected(token: String) {
        try {
            TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
            fail("Expected verifyJwt to reject the token but it was accepted")
        } catch (expected: Exception) {
        }
    }

    /**
     * Asserts the token is rejected specifically by claim verification ([BadJWTException]), so a
     * crafted token can't pass by being rejected for an unrelated reason.
     */
    private fun assertClaimRejected(token: String) {
        try {
            TokenVerifier.verifyJwt(token, jwkSource, issuer, audience, 60)
            fail("Expected verifyJwt to reject the token on a claim check but it was accepted")
        } catch (expected: BadJWTException) {
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
        return sign(key, claims)
    }

    /** A valid token carrying an explicit `azp`, optionally addressed to more than one audience. */
    private fun mintWithAzp(
        azp: String?,
        audiences: List<String> = listOf(audience),
        nonce: String? = null,
    ): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder().apply {
            subject("user-123")
            issuer(issuer)
            audience(audiences)
            expirationTime(Date(now + 3600 * 1000))
            issueTime(Date(now))
            azp?.let { claim("azp", it) }
            nonce?.let { claim("nonce", it) }
        }.build()
        return sign(signingKey, claims)
    }

    /** An otherwise fully valid token whose header names [alg] instead of RS256. */
    private fun signWithAlg(alg: JWSAlgorithm): String {
        val claims = JWTClaimsSet.Builder()
            .subject("user-123").issuer(issuer).audience(audience)
            .expirationTime(Date(System.currentTimeMillis() + 3_600_000))
            .build()
        val signed = SignedJWT(JWSHeader.Builder(alg).keyID(signingKey.keyID).build(), claims)
        signed.sign(RSASSASigner(signingKey))
        return signed.serialize()
    }

    private fun sign(key: RSAKey, claims: JWTClaimsSet): String {
        val signed = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims)
        signed.sign(RSASSASigner(key))
        return signed.serialize()
    }

    companion object {
        private const val KID = "test-key"
    }
}
