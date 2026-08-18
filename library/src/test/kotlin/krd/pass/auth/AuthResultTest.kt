package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AuthResultTest {

    @Test
    fun `canonical message is exposed for the bare result cases`() {
        assertNull(AuthResult.Success("code", "state").message)
        assertEquals("Authentication was cancelled", AuthResult.Cancelled.message)
        assertEquals("Authentication timed out", AuthResult.Timeout.message)
        assertEquals("Another authentication is already in progress", AuthResult.Busy.message)
    }

    @Test
    fun `canonical message strings are byte-identical with the other SDKs`() {
        // Guards cross-SDK parity: these must stay byte-for-byte equal across Flutter/iOS/RN/Android.
        assertEquals("Authentication was cancelled", KrdpassMessages.CANCELLED)
        assertEquals("Authentication timed out", KrdpassMessages.TIMEOUT)
        assertEquals("Another authentication is already in progress", KrdpassMessages.BUSY)
        assertEquals(
            "The KRDPASS app is not installed or could not be opened. Please install or update KRDPASS.",
            KrdpassMessages.PROVIDER_NOT_INSTALLED,
        )
        assertEquals(
            "State parameter mismatch: possible CSRF or response injection",
            KrdpassMessages.STATE_MISMATCH,
        )
        assertEquals(
            "Issuer mismatch: the response did not come from the expected authorization server",
            KrdpassMessages.ISSUER_MISMATCH,
        )
        assertEquals("No authorization code received", KrdpassMessages.NO_CODE)
        assertEquals("Redirect URI does not match the exact configured endpoint", KrdpassMessages.INVALID_REDIRECT)
        assertEquals(
            "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn().",
            KrdpassMessages.STATE_REQUIRED,
        )
        assertEquals("Token response did not include an id_token", KrdpassMessages.MISSING_ID_TOKEN)
        assertEquals("ID token nonce mismatch (possible token replay)", KrdpassMessages.NONCE_MISMATCH)
    }

    @Test
    fun `KrdpassError exposes the same wire codes as the other SDKs`() {
        // The bridges forward KrdpassError.code straight to Dart/TypeScript, so these strings are
        // the contract; they must stay byte-for-byte equal across Flutter/iOS/RN/Android.
        assertEquals("cancelled", KrdpassError.UserCancelled().code)
        assertEquals("timeout", KrdpassError.Timeout().code)
        assertEquals("busy", KrdpassError.Busy().code)
        assertEquals("network_error", KrdpassError.NetworkError("boom").code)
        assertEquals("invalid_request", KrdpassError.ConfigurationError("boom").code)
        // AuthenticationFailed passes its own code through, null included.
        assertEquals("state_mismatch", KrdpassError.AuthenticationFailed("boom", "state_mismatch").code)
        assertNull(KrdpassError.AuthenticationFailed("boom").code)
    }

    @Test
    fun `Error result properties are correct`() {
        val result = AuthResult.Error("test_error", "Test description")

        assertEquals("test_error", result.error)
        assertEquals("Test description", result.errorDescription)
        assertEquals("Test description", result.message)
    }

    @Test
    fun `Error result without description uses error as message`() {
        val result = AuthResult.Error("test_error")

        assertEquals("test_error", result.message)
        assertNull(result.errorDescription)
    }

    @Test
    fun `AuthErrorCode round-trips every known wire string`() {
        // fromWire(wire) must recover the same entry for every code the enum declares: guards
        // against a typo'd wire literal silently producing a null typed view.
        for (code in AuthErrorCode.entries) {
            assertEquals(code, AuthErrorCode.fromWire(code.wire))
        }
    }

    @Test
    fun `Error code is typed for known codes and null for passthrough codes`() {
        assertEquals(AuthErrorCode.PROVIDER_NOT_INSTALLED, AuthResult.Error("provider_not_installed").code)
        assertEquals(AuthErrorCode.STATE_MISMATCH, AuthResult.Error("state_mismatch").code)
        // An OAuth provider may return an arbitrary code; it stays in `error` but maps to no enum.
        assertNull(AuthResult.Error("some_provider_specific_error").code)
        assertEquals("some_provider_specific_error", AuthResult.Error("some_provider_specific_error").error)
    }

    @Test
    fun `logLabel names the outcome without leaking the code or the upstream description`() {
        assertEquals("success", AuthResult.Success("real-authorization-code", "state").logLabel)
        assertEquals("cancelled", AuthResult.Cancelled.logLabel)
        assertEquals("timeout", AuthResult.Timeout.logLabel)
        assertEquals("busy", AuthResult.Busy.logLabel)
        assertEquals("error(state_mismatch)", AuthResult.Error("state_mismatch").logLabel)
        // A passthrough provider code still reaches the log; only the description is withheld.
        assertEquals(
            "error(some_provider_specific_error)",
            AuthResult.Error("some_provider_specific_error", "upstream detail").logLabel,
        )

        // The two payloads that must never reach a logger.
        assertFalse(AuthResult.Success("real-authorization-code").logLabel.contains("real-authorization-code"))
        assertFalse(AuthResult.Error("bad", "upstream detail").logLabel.contains("upstream detail"))
    }

    @Test
    fun `isCancelled covers both cancellation shapes and nothing else`() {
        // The two shapes: the user returned without responding (Cancelled), and a deny KRDPASS
        // reported on the redirect, which decideAuthResult canonicalizes to Error("cancelled").
        assertTrue(AuthResult.Cancelled.isCancelled)
        assertTrue(AuthResult.Error("cancelled", "not eligible for citizen_identity").isCancelled)

        assertFalse(AuthResult.Success("code").isCancelled)
        assertFalse(AuthResult.Timeout.isCancelled)
        assertFalse(AuthResult.Busy.isCancelled)
        assertFalse(AuthResult.Error("timeout").isCancelled)
        // Aliases never reach a caller: decideAuthResult rewrites them before Error is built.
        assertFalse(AuthResult.Error("access_denied").isCancelled)
    }

    @Test
    fun `every result case is distinguished by pattern matching, not by a boolean getter`() {
        // isCancelled is the one deliberate is* getter (its two-shape story spans subtypes, and
        // Flutter/RN ship the same helper); everything else is matched on the sealed subtype.
        val cases: List<AuthResult> = listOf(
            AuthResult.Success("code", "state"),
            AuthResult.Cancelled,
            AuthResult.Timeout,
            AuthResult.Busy,
            AuthResult.Error("provider_not_installed"),
        )
        assertEquals(cases.size, cases.map { it::class }.toSet().size)
        assertEquals(
            AuthErrorCode.PROVIDER_NOT_INSTALLED,
            (cases.last() as AuthResult.Error).code,
        )
    }
}
