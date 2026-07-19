package krd.pass.auth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Covers the stateless, launch-decoupled API that both the Activity adapter and the React Native
 * binding share: [KrdpassAuth.startAuthentication] (arg validation + fail-closed provider cert-pin)
 * and [KrdpassAuth.handleAuthorizationResult] (Intent/Uri extraction -> the pure [decideAuthResult]).
 * The decision policy itself is exhaustively covered by AuthResultDecisionTest; this asserts the
 * Android-side extraction wired to it.
 */
@RunWith(RobolectricTestRunner::class)
class LaunchDecoupledApiTest {

    private val config = KrdpassConfig(
        clientId = "client",
        redirectUri = "https://app.example.com/callback",
        environment = KrdpassEnvironment.Development,
    )
    private val sentState = "sent-state"

    private fun redirect(query: String): Intent =
        Intent().setData(Uri.parse("https://app.example.com/callback?$query"))

    // --- handleAuthorizationResult: Intent extraction delegated to decideAuthResult ---

    @Test
    fun `success extracts code and state from the redirect`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK, redirect("code=abc&state=$sentState"), config, sentState)
        assertTrue(r is AuthResult.Success)
        r as AuthResult.Success
        assertEquals("abc", r.code)
        assertEquals(sentState, r.state)
    }

    @Test
    fun `RESULT_CANCELED is a cancellation`() {
        val r = KrdpassAuth.handleAuthorizationResult(Activity.RESULT_CANCELED, null, config, sentState)
        assertTrue(r is AuthResult.Cancelled)
    }

    @Test
    fun `a mismatched state is rejected as CSRF`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK, redirect("code=abc&state=attacker"), config, sentState)
        assertError(r, "state_mismatch")
    }

    @Test
    fun `access_denied is canonicalized to cancelled`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK, redirect("error=access_denied&error_description=no&state=$sentState"), config, sentState)
        assertError(r, "cancelled")
    }

    @Test
    fun `a redirect on a different host is rejected`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            Intent().setData(Uri.parse("https://evil.example.com/callback?code=abc&state=$sentState")),
            config, sentState)
        assertError(r, "invalid_redirect")
    }

    @Test
    fun `neither code nor error yields no_code`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK, redirect("foo=bar"), config, sentState)
        assertError(r, "no_code")
    }

    // --- startAuthentication: arg validation + fail-closed cert-pin ---

    @Test
    fun `blank requestUri fails`() {
        assertLaunchFailure(KrdpassAuth.startAuthentication(null, config, "", sentState), "platform_error")
    }

    @Test
    fun `blank state fails`() {
        assertLaunchFailure(KrdpassAuth.startAuthentication(null, config, "urn:req", ""), "invalid_request")
    }

    @Test
    fun `no Context with a configured pin fails closed`() {
        // Development pins a cert, so a null Context cannot verify the provider -> fail closed.
        assertLaunchFailure(
            KrdpassAuth.startAuthentication(null, config, "urn:req", sentState), "provider_not_installed")
    }

    private fun assertError(result: AuthResult, code: String) {
        assertTrue("Expected AuthResult.Error but was $result", result is AuthResult.Error)
        assertEquals(code, (result as AuthResult.Error).error)
    }

    private fun assertLaunchFailure(launch: KrdpassAuth.AuthLaunch, code: String) {
        assertTrue("Expected AuthLaunch.Failure but was $launch", launch is KrdpassAuth.AuthLaunch.Failure)
        assertEquals(code, (launch as KrdpassAuth.AuthLaunch.Failure).error.error)
    }
}
