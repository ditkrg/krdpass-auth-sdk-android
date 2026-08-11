package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

@RunWith(RobolectricTestRunner::class)
class KrdpassAuthCoreTest {

    @Test
    fun `buildAuthorizationUrl constructs correct OAuth URL`() {
        val config = KrdpassConfig("test_client", "https://example.com/callback", KrdpassEnvironment.Production)
        val requestUri = "urn:ietf:params:oauth:request_uri:abc123"

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
    fun `KrdpassTokenResult redacts every credential in toString`() {
        val result = KrdpassTokenResult(
            accessToken = "access_123",
            idToken = "id_123",
            tokenType = "Bearer",
            expiresIn = 3600,
            refreshToken = "refresh_123",
            scope = "openid profile"
        )

        val text = result.toString()
        assertFalse("access token must not appear", text.contains("access_123"))
        assertFalse("id token must not appear", text.contains("id_123"))
        assertFalse("refresh token must not appear", text.contains("refresh_123"))
        // Non-sensitive fields stay readable so the value is still debuggable.
        assertTrue(text.contains("Bearer"))
        assertTrue(text.contains("openid profile"))
    }

    @Test
    fun `KrdpassTokenResult distinguishes an absent token from a redacted one`() {
        val minimal = KrdpassTokenResult(
            accessToken = "access_only",
            idToken = null,
            tokenType = "Bearer",
            expiresIn = 7200,
            refreshToken = null,
            scope = null
        )

        val text = minimal.toString()
        assertTrue("a null id token reads as null, not [REDACTED]", text.contains("idToken=null"))
        assertTrue(text.contains("refreshToken=null"))
    }

    @Test
    fun `boundToParExpiry caps the timeout at the PAR request_uri lifetime`() {
        assertEquals(30.seconds, KrdpassAuth.boundToParExpiry(5.minutes, 30))
    }

    @Test
    fun `boundToParExpiry keeps the requested timeout when it is shorter`() {
        assertEquals(60.seconds, KrdpassAuth.boundToParExpiry(60.seconds, 600))
    }
}
