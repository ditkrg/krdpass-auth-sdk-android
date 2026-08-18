package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PkceGeneratorTest {

    @Test
    fun `generate() creates valid PKCE pair with S256 method`() {
        val pair = PkceGenerator.generate()

        assertEquals("S256", pair.method)

        // RFC 7636 requires 43-128 characters. Asserted as literals: the generator must be
        // checked against the RFC, not against a constant it also defines.
        assertTrue(pair.codeVerifier.length in 43..128)

        val base64UrlPattern = Regex("^[A-Za-z0-9_-]+$")
        assertTrue(base64UrlPattern.matches(pair.codeVerifier))

        val expectedChallenge = PkceGenerator.computeChallenge(pair.codeVerifier)
        assertEquals(expectedChallenge, pair.codeChallenge)
    }

    @Test
    fun `computeChallenge() produces correct S256 hash for known input`() {
        // Test vector from RFC 7636 Appendix B
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        val actualChallenge = PkceGenerator.computeChallenge(verifier)

        assertEquals(expectedChallenge, actualChallenge)
    }

    @Test
    fun `computeChallenge() produces no padding in output`() {
        val verifier = "test_verifier"
        val challenge = PkceGenerator.computeChallenge(verifier)

        assertFalse(challenge.contains('='))
    }

    @Test
    fun `computeChallenge() is deterministic for same input`() {
        val verifier = "same_input_every_time"
        val challenge1 = PkceGenerator.computeChallenge(verifier)
        val challenge2 = PkceGenerator.computeChallenge(verifier)

        assertEquals(challenge1, challenge2)
    }

    @Test
    fun `generated pairs are unique`() {
        val pairs = List(100) { PkceGenerator.generate() }

        val verifiers = pairs.map { it.codeVerifier }
        assertEquals(verifiers.size, verifiers.toSet().size)

        val challenges = pairs.map { it.codeChallenge }
        assertEquals(challenges.size, challenges.toSet().size)
    }

    @Test
    fun `verifier contains only URL-safe base64 characters`() {
        val pair = PkceGenerator.generate()

        val allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        pair.codeVerifier.forEach { char ->
            assertTrue("Character '$char' not in base64url alphabet", char in allowedChars)
        }
    }

    @Test
    fun `challenge contains only URL-safe base64 characters`() {
        val pair = PkceGenerator.generate()

        assertFalse(pair.codeChallenge.contains('+'))
        assertFalse(pair.codeChallenge.contains('/'))
        assertFalse(pair.codeChallenge.contains('='))
    }
}

