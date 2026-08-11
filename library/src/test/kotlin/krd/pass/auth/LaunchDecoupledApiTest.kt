package krd.pass.auth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.core.app.ActivityOptionsCompat
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Covers the stateless, launch-decoupled API: [KrdpassAuth.startAuthentication] and
 * [KrdpassAuth.handleAuthorizationResult]. The decision policy itself is exhaustively covered by
 * AuthResultDecisionTest; this asserts the Android-side extraction wired to it.
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
    fun `a redirect on a different path is rejected`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            Intent().setData(Uri.parse("https://app.example.com/other?code=abc&state=$sentState")),
            config,
            sentState,
        )

        assertError(r, "invalid_redirect")
    }

    @Test
    fun `duplicate state is rejected before response parsing`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            redirect("code=abc&state=$sentState&state=attacker"),
            config,
            sentState,
        )

        assertError(r, "invalid_redirect")
    }

    @Test
    fun `blank security response parameter is rejected as malformed`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            redirect("code=&state=$sentState"),
            config,
            sentState,
        )

        assertError(r, "invalid_redirect")
    }

    @Test
    fun `configured query parameter remains part of the redirect match`() {
        val fixedQueryConfig = config.copy(redirectUri = "https://app.example.com/callback?tenant=krd")

        val accepted = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            Intent().setData(Uri.parse("https://app.example.com/callback?tenant=krd&code=abc&state=$sentState")),
            fixedQueryConfig,
            sentState,
        )
        val rejected = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            Intent().setData(Uri.parse("https://app.example.com/callback?code=abc&state=$sentState")),
            fixedQueryConfig,
            sentState,
        )

        assertTrue(accepted is AuthResult.Success)
        assertError(rejected, "invalid_redirect")
    }

    @Test
    fun `single-valued response metadata is ignored`() {
        val r = KrdpassAuth.handleAuthorizationResult(
            Activity.RESULT_OK,
            redirect("code=abc&state=$sentState&session_state=server-session"),
            config,
            sentState,
        )
        assertTrue(r is AuthResult.Success)
    }

    /**
     * Comparing against a plain `makeBasic()` bag is what gives this teeth: dropping
     * `setShareIdentityEnabled(true)` makes the two identical and fails the test.
     */
    @Test
    @Config(sdk = [34])
    fun `ready launch enables caller identity sharing`() {
        val shared = KrdpassAuth.AuthLaunch.Ready(Intent(Intent.ACTION_VIEW)).activityOptions
        val plain = ActivityOptionsCompat.makeBasic().toBundle()

        assertNotEquals(plain?.keySet(), shared?.keySet())
    }

    @Test
    fun `ready keeps the single-argument constructor and copy`() {
        val ready = KrdpassAuth.AuthLaunch.Ready(Intent(Intent.ACTION_VIEW))
        val other = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.test"))

        assertEquals(other, ready.copy(intent = other).intent)
    }

    @Test
    fun `a flight settles exactly once and the winner delivers`() {
        // The whole cancel/timeout/result race reduces to this: a cancel arriving during signIn's
        // PAR round trip settles the flight, and the launch that follows must find it settled
        // rather than open KRDPASS for an abandoned flow.
        val flight = Flight()
        var delivered: AuthResult? = null

        assertTrue("the cancel claims the outcome", flight.settle(AuthResult.Cancelled))
        assertFalse("a second settle must not win", flight.settle(AuthResult.Timeout))
        assertEquals(AuthResult.Cancelled, flight.result)
        // Installed after the settle: the waiter takes the outcome itself instead of hanging.
        assertEquals(AuthResult.Cancelled, flight.awaitOn { delivered = it })
        assertNull("the settler must not also deliver to it", delivered)
        assertNull("and the waiter is spent", flight.takeWaiter())
    }

    @Test
    fun `a SignInPending cannot be finished twice`() = runBlocking {
        val pending = KrdpassAuth.SignInPending("verifier", sentState, "nonce", 300)

        val first = runCatching {
            KrdpassAuth.finishSignIn(Activity.RESULT_CANCELED, null, config, pending)
        }.exceptionOrNull()
        val second = runCatching {
            KrdpassAuth.finishSignIn(Activity.RESULT_CANCELED, null, config, pending)
        }.exceptionOrNull()

        assertTrue("the first use settles the real outcome, was $first", first is KrdpassError.UserCancelled)
        // Replaying it would reuse the code verifier and nonce; refuse it here instead of letting
        // the server answer with a confusing invalid_grant.
        assertTrue("a replayed pending is refused, was $second", second is KrdpassError.ConfigurationError)
    }

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
