package krd.pass.auth

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PkceGeneratorTest {

    @Test
    fun `generate() creates valid PKCE pair with S256 method`() {
        val pair = PkceGenerator.generate()

        // Check method
        assertEquals("S256", pair.method)

        // Check verifier length (43-128 characters)
        assertTrue(pair.codeVerifier.length in PkceGenerator.MIN_VERIFIER_LENGTH..PkceGenerator.MAX_VERIFIER_LENGTH)

        // Check verifier is base64url alphabet
        val base64UrlPattern = Regex("^[A-Za-z0-9_-]+$")
        assertTrue(base64UrlPattern.matches(pair.codeVerifier))

        // Check challenge is derived from verifier
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

        // Base64url should not contain padding characters
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

        // Check all verifiers are unique
        val verifiers = pairs.map { it.codeVerifier }
        assertEquals(verifiers.size, verifiers.toSet().size)

        // Check all challenges are unique
        val challenges = pairs.map { it.codeChallenge }
        assertEquals(challenges.size, challenges.toSet().size)
    }

    @Test
    fun `verifier contains only URL-safe base64 characters`() {
        val pair = PkceGenerator.generate()

        // RFC 7636 requires base64url alphabet: A-Z, a-z, 0-9, -, _
        val allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        pair.codeVerifier.forEach { char ->
            assertTrue("Character '$char' not in base64url alphabet", char in allowedChars)
        }
    }

    @Test
    fun `challenge contains only URL-safe base64 characters`() {
        val pair = PkceGenerator.generate()

        // Base64url should not contain +, /, or =
        assertFalse(pair.codeChallenge.contains('+'))
        assertFalse(pair.codeChallenge.contains('/'))
        assertFalse(pair.codeChallenge.contains('='))
    }
}

