package krd.pass.auth

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KrdpassAuthCoreTest {

    @Test
    fun `buildAuthorizationUrl constructs correct OAuth URL`() {
        // Test the URL construction logic using the internal method
        val config = KrdpassConfig("test_client", "https://example.com/callback", KrdpassEnvironment.Production)
        val requestUri = "urn:ietf:params:oauth:request_uri:abc123"

        // Use the actual implementation
        val authUrl = KrdpassAuth.buildAuthorizationUrl(config, requestUri, null)

        assertTrue("URL should contain client_id", authUrl.contains("client_id=test_client"))
        assertTrue("URL should contain request_uri", authUrl.contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc123"))
        assertTrue("URL should contain redirect_uri", authUrl.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
        assertTrue("URL should start with auth URL", authUrl.startsWith("https://app.pass.krd/connect/authorize?"))
    }

    @Test
    fun `buildAuthorizationUrl works with development environment`() {
        val config = KrdpassConfig("dev_client", "https://dev.example.com/callback", KrdpassEnvironment.Development)
        val requestUri = "urn:ietf:params:oauth:request_uri:dev123"

        val authUrl = KrdpassAuth.buildAuthorizationUrl(config, requestUri, null)

        assertTrue("Dev URL should start with dev auth URL", authUrl.startsWith("https://app.krdpass.dev.krd/connect/authorize?"))
        assertTrue("Dev URL should contain dev client_id", authUrl.contains("client_id=dev_client"))
    }

    @Test
    fun `KrdpassTokenResult handles all optional fields correctly`() {
        val fullResult = KrdpassTokenResult(
            accessToken = "access_123",
            idToken = "id_123",
            tokenType = "Bearer",
            expiresIn = 3600,
            refreshToken = "refresh_123",
            scope = "openid profile"
        )

        assertEquals("access_123", fullResult.accessToken)
        assertEquals("id_123", fullResult.idToken)
        assertEquals("Bearer", fullResult.tokenType)
        assertEquals(3600, fullResult.expiresIn)
        assertEquals("refresh_123", fullResult.refreshToken)
        assertEquals("openid profile", fullResult.scope)

        val minimalResult = KrdpassTokenResult(
            accessToken = "access_only",
            idToken = null,
            tokenType = "Custom",
            expiresIn = 7200,
            refreshToken = null,
            scope = null
        )

        assertEquals("access_only", minimalResult.accessToken)
        assertNull(minimalResult.idToken)
        assertEquals("Custom", minimalResult.tokenType)
        assertEquals(7200, minimalResult.expiresIn)
        assertNull(minimalResult.refreshToken)
        assertNull(minimalResult.scope)
    }

    @Test
    fun `ParResponse stores request URI and expiry correctly`() {
        val response = ParResponse("urn:test:request:123", 600)
        assertEquals("urn:test:request:123", response.requestUri)
        assertEquals(600, response.expiresIn)
    }

    @Test
    fun `CasException formats error messages correctly`() {
        val exception = CasException("Test error", 400)
        assertEquals("Test error", exception.message)
        assertEquals(400, exception.statusCode)

        val message = exception.toString()
        assertTrue(message.contains("CasException"))
        assertTrue(message.contains("Test error"))
        assertTrue(message.contains("(status: 400)"))
    }

    @Test
    fun `CasException handles null status code`() {
        val exception = CasException("Network error", null, null)
        val message = exception.toString()
        assertTrue(message.contains("CasException"))
        assertTrue(message.contains("Network error"))
        assertFalse(message.contains("(status:"))
    }
}