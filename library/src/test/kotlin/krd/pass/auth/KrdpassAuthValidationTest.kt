package krd.pass.auth

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KrdpassAuthValidationTest {

    @Test
    fun `KrdpassConfig can be created with valid parameters`() {
        val config = KrdpassConfig("client123", "https://example.com/callback")
        assertNotNull(config)
        assertEquals("client123", config.clientId)
        assertEquals("https://example.com/callback", config.redirectUri)
    }

    @Test
    fun `KrdpassEnvironment has correct URLs`() {
        assertEquals("https://app.pass.krd/connect/authorize", KrdpassEnvironment.Production.authUrl)
        assertEquals("https://account.id.krd", KrdpassEnvironment.Production.authServerUrl)

        assertEquals("https://app.krdpass.dev.krd/connect/authorize", KrdpassEnvironment.Development.authUrl)
        assertEquals("https://auth.dev.krd", KrdpassEnvironment.Development.authServerUrl)
    }

    @Test
    fun `buildAuthorizationUrl constructs correct URL`() {
        // Test that we can use the internal URL construction
        val config = KrdpassConfig("test_client", "https://example.com/callback", KrdpassEnvironment.Production)
        val requestUri = "urn:ietf:params:oauth:request_uri:test123"

        val expectedUrl = KrdpassAuth.buildAuthorizationUrl(config, requestUri, null)

        assertTrue(expectedUrl.contains("client_id=test_client"))
        assertTrue(expectedUrl.contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest123"))
        assertTrue(expectedUrl.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
    }

    @Test
    fun `generatePkcePair creates valid pairs`() {
        val pair = PkceGenerator.generate()

        assertNotNull(pair.codeVerifier)
        assertNotNull(pair.codeChallenge)
        assertEquals("S256", pair.method)

        // Verify challenge is derived from verifier
        val expectedChallenge = PkceGenerator.computeChallenge(pair.codeVerifier)
        assertEquals(expectedChallenge, pair.codeChallenge)
    }
}