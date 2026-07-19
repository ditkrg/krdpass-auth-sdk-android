package krd.pass.auth

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AuthResultTest {

    @Test
    fun `Success result properties are correct`() {
        val result = AuthResult.Success("code123", "state456")

        assertTrue(result.isSuccess)
        assertFalse(result.isCancelled)
        assertFalse(result.isTimeout)
        assertFalse(result.isBusy)
        assertFalse(result.isError)
    }

    @Test
    fun `Cancelled result properties are correct`() {
        val result = AuthResult.Cancelled

        assertFalse(result.isSuccess)
        assertTrue(result.isCancelled)
        assertFalse(result.isTimeout)
        assertFalse(result.isBusy)
        assertFalse(result.isError)
    }

    @Test
    fun `Timeout result properties are correct`() {
        val result = AuthResult.Timeout

        assertFalse(result.isSuccess)
        assertFalse(result.isCancelled)
        assertTrue(result.isTimeout)
        assertFalse(result.isBusy)
        assertFalse(result.isError)
    }

    @Test
    fun `Busy result properties are correct`() {
        val result = AuthResult.Busy

        assertFalse(result.isSuccess)
        assertFalse(result.isCancelled)
        assertFalse(result.isTimeout)
        assertTrue(result.isBusy)
        assertFalse(result.isError)
    }

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
        assertEquals("No authorization code received", KrdpassMessages.NO_CODE)
        assertEquals("Redirect URI does not match configured host", KrdpassMessages.INVALID_REDIRECT)
        assertEquals(
            "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn().",
            KrdpassMessages.STATE_REQUIRED,
        )
        assertEquals("Token response did not include an id_token", KrdpassMessages.MISSING_ID_TOKEN)
        assertEquals("ID token nonce mismatch (possible token replay)", KrdpassMessages.NONCE_MISMATCH)
    }

    @Test
    fun `Error result properties are correct`() {
        val result = AuthResult.Error("test_error", "Test description")

        assertFalse(result.isSuccess)
        assertFalse(result.isCancelled)
        assertFalse(result.isTimeout)
        assertFalse(result.isBusy)
        assertTrue(result.isError)
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
    fun `isProviderNotInstalled is true only for the provider_not_installed code`() {
        assertTrue(AuthResult.Error("provider_not_installed").isProviderNotInstalled)
        assertFalse(AuthResult.Error("state_mismatch").isProviderNotInstalled)
        assertFalse(AuthResult.Cancelled.isProviderNotInstalled)
    }
}

