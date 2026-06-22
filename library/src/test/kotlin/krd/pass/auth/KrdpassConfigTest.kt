package krd.pass.auth

import android.net.Uri
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KrdpassConfigTest {

    @Rule
    @JvmField
    val globalTimeout: Timeout = Timeout.seconds(30)

    @Test
    fun `isValidRedirectUri() rejects custom schemes`() {
        val config = KrdpassConfig("test-client-id", "myapp://callback")

        val testUri = Uri.parse("myapp://callback")

        // Should reject even if scheme matches - only HTTPS allowed
        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts exact HTTPS match`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/callback")

        assertTrue(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() rejects HTTPS with different host`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://evil.com/auth/callback")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() rejects HTTPS with different port`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com:8443/auth/callback")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts HTTPS with different path`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/wrong")

        assertTrue(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() rejects HTTP scheme even with correct host and path`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("http://example.com/auth/callback")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts query parameters in redirect URI`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/callback?code=123&state=abc")

        assertTrue(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts when path differs with query params`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/wrong?code=123")

        assertTrue(config.isValidRedirectUri(testUri))
    }


    @Test
    fun `isValidRedirectUri() with string URL calls URI version`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        // Test that string version delegates to URI version
        assertTrue(config.isValidRedirectUri("https://example.com/auth/callback"))
        assertFalse(config.isValidRedirectUri("https://evil.com/auth/callback"))
    }

    // Note: KrdpassConfig itself doesn't validate - validation happens in KrdpassAuth.initialize()
}
