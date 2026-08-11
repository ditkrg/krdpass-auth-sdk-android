package krd.pass.auth

import android.net.Uri
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KrdpassConfigTest {

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
    fun `isValidRedirectUri() rejects HTTPS with a different path`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/wrong")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() rejects HTTP scheme even with correct host and path`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("http://example.com/auth/callback")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts OAuth response parameters on the exact redirect`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback?tenant=krd")

        val testUri = Uri.parse("https://example.com/auth/callback?tenant=krd&code=123&state=abc")

        assertTrue(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() rejects when path differs with query params`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        val testUri = Uri.parse("https://example.com/auth/wrong?code=123")

        assertFalse(config.isValidRedirectUri(testUri))
    }

    @Test
    fun `isValidRedirectUri() accepts the explicit HTTPS default port`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        assertTrue(config.isValidRedirectUri(Uri.parse("https://example.com:443/auth/callback?code=123")))
    }

    @Test
    fun `isValidRedirectUri() matches HTTPS scheme and host without case sensitivity`() {
        val config = KrdpassConfig("test-client-id", "HTTPS://EXAMPLE.COM/auth/callback")

        assertTrue(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?code=123")))
    }

    @Test
    fun `isValidRedirectUri() requires every configured query entry`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback?tenant=krd&ui=mobile")

        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?tenant=krd&code=123")))
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?tenant=other&ui=mobile&code=123")))
    }

    @Test
    fun `isValidRedirectUri() preserves configured fixed-query multiplicity independent of order`() {
        val config = KrdpassConfig(
            "test-client-id",
            "https://example.com/auth/callback?tenant=krd&tenant=krd&ui=mobile",
        )

        assertTrue(
            config.isValidRedirectUri(
                Uri.parse("https://example.com/auth/callback?ui=mobile&code=123&tenant=krd&tenant=krd"),
            ),
        )
        assertFalse(
            config.isValidRedirectUri(
                Uri.parse("https://example.com/auth/callback?ui=mobile&tenant=krd&code=123"),
            ),
        )
    }

    @Test
    fun `isValidRedirectUri() ignores response metadata but rejects ambiguous parameters`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback?tenant=krd")

        assertTrue(
            config.isValidRedirectUri(
                Uri.parse(
                    "https://example.com/auth/callback?tenant=krd&code=one&state=abc&session_state=server-session",
                ),
            ),
        )
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?tenant=krd&code=one&code=two")))
        assertFalse(
            config.isValidRedirectUri(
                Uri.parse(
                    "https://example.com/auth/callback?tenant=krd&code=one&state=abc&session_state=one&session_state=two",
                ),
            ),
        )
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?tenant=krd&code=one&error=access_denied")))
        assertFalse(
            config.isValidRedirectUri(
                Uri.parse("https://example.com/auth/callback?tenant=krd&tenant=attacker&code=one&state=abc"),
            ),
        )
    }

    @Test
    fun `isValidRedirectUri() rejects fragments user info and malformed encoding`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        assertFalse(config.isValidRedirectUri(Uri.parse("https://user@example.com/auth/callback?code=123")))
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?code=123#fragment")))
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/%?code=123")))
        assertFalse(config.isValidRedirectUri(Uri.parse("https://example.com/auth/callback?code=%")))
    }


    @Test
    fun `isValidRedirectUri() with string URL calls URI version`() {
        val config = KrdpassConfig("test-client-id", "https://example.com/auth/callback")

        assertTrue(config.isValidRedirectUri("https://example.com/auth/callback"))
        assertFalse(config.isValidRedirectUri("https://evil.com/auth/callback"))
    }

    // KrdpassConfig itself does not validate; that happens in KrdpassAuth.initialize().
}
