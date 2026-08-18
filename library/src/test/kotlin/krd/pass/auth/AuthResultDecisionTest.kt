package krd.pass.auth

import android.app.Activity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the fail-closed auth-result decision returned to the caller after KRDPASS hands the
 * result back via the Activity result (app-to-app). This is the SDK's CSRF / response-injection
 * defense: a returned authorization code is accepted ONLY when the redirect matched and the
 * returned state equals the state we sent. Every accept/reject branch is asserted here.
 */
class AuthResultDecisionTest {

    private val sentState = "the-state-we-sent"
    private val ourIssuer = "https://account.id.krd"

    private fun decide(
        resultCode: Int = Activity.RESULT_OK,
        hasUriData: Boolean = true,
        redirectValid: Boolean = true,
        code: String? = null,
        returnedState: String? = null,
        error: String? = null,
        errorDescription: String? = null,
        expectedState: String? = sentState,
        returnedIss: String? = null,
        expectedIssuer: String? = ourIssuer,
    ): AuthResult = KrdpassAuth.decideAuthResult(
        resultCode, hasUriData, redirectValid, code, returnedState, error, errorDescription, expectedState,
        returnedIss, expectedIssuer,
    )

    @Test
    fun `a code with a matching state is a success`() {
        val result = decide(code = "auth-code-xyz", returnedState = sentState)
        assertTrue(result is AuthResult.Success)
        result as AuthResult.Success
        assertEquals("auth-code-xyz", result.code)
        assertEquals(sentState, result.state)
    }

    @Test
    fun `a code with a mismatched state is rejected (CSRF)`() {
        val result = decide(code = "auth-code-xyz", returnedState = "attacker-state")
        assertError(result, "state_mismatch")
    }

    @Test
    fun `a code with no returned state is rejected`() {
        val result = decide(code = "auth-code-xyz", returnedState = null)
        assertError(result, "state_mismatch")
    }

    @Test
    fun `a code is rejected when we never recorded an expected state`() {
        val result = decide(code = "auth-code-xyz", returnedState = sentState, expectedState = null)
        assertError(result, "state_mismatch")
    }

    @Test
    fun `a code arriving on a non-matching redirect host is rejected`() {
        val result = decide(code = "auth-code-xyz", returnedState = sentState, redirectValid = false)
        assertError(result, "invalid_redirect")
    }

    @Test
    fun `access_denied is canonicalized to cancelled`() {
        val result = decide(error = "access_denied", errorDescription = "User said no", returnedState = sentState)
        assertError(result, "cancelled")
    }

    @Test
    fun `login_required and consent_denied are also canonicalized to cancelled`() {
        assertError(decide(error = "login_required", returnedState = sentState), "cancelled")
        assertError(decide(error = "consent_denied", returnedState = sentState), "cancelled")
        assertError(decide(error = "user_cancelled", returnedState = sentState), "cancelled")
    }

    @Test
    fun `an unknown provider error is passed through verbatim with its description`() {
        val result = decide(error = "server_error", errorDescription = "boom", returnedState = sentState)
        assertTrue(result is AuthResult.Error)
        result as AuthResult.Error
        assertEquals("server_error", result.error)
        assertEquals("boom", result.errorDescription)
    }

    @Test
    fun `neither a code nor an error yields no_code`() {
        assertError(decide(code = null, error = null), "no_code")
    }

    @Test
    fun `a cancelled result code is a cancellation`() {
        val result = decide(resultCode = Activity.RESULT_CANCELED)
        assertTrue(result is AuthResult.Cancelled)
    }

    @Test
    fun `an OK result with no uri data is a platform error`() {
        assertError(decide(hasUriData = false), "platform_error")
    }

    @Test
    fun `an unexpected result code is a platform error`() {
        assertError(decide(resultCode = 42), "platform_error")
    }

    @Test
    fun `an error with a matching state is accepted`() {
        val result = decide(error = "server_error", returnedState = sentState)
        assertError(result, "server_error")
    }

    @Test
    fun `an error with a mismatched state is rejected (CSRF)`() {
        val result = decide(error = "server_error", returnedState = "attacker-state")
        assertError(result, "state_mismatch")
    }

    @Test
    fun `an error with no returned state is rejected`() {
        val result = decide(error = "server_error", returnedState = null)
        assertError(result, "state_mismatch")
    }

    @Test
    fun `a cancellation error with a matching state is accepted`() {
        val result = decide(error = "access_denied", returnedState = sentState)
        assertError(result, "cancelled")
    }

    @Test
    fun `a cancellation error with a mismatched state is rejected (CSRF)`() {
        val result = decide(error = "access_denied", returnedState = "attacker-state")
        assertError(result, "state_mismatch")
    }

    @Test
    fun `a code with a matching iss is a success`() {
        val result = decide(code = "auth-code-xyz", returnedState = sentState, returnedIss = ourIssuer)
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `a code with a mismatched iss is rejected (mix-up)`() {
        val result = decide(code = "auth-code-xyz", returnedState = sentState, returnedIss = "https://attacker.example")
        assertError(result, "issuer_mismatch")
    }

    @Test
    fun `iss is compared exactly, without URL normalisation`() {
        // Same convention as the id_token iss claim check in TokenVerifier: exact string equality.
        val result = decide(code = "auth-code-xyz", returnedState = sentState, returnedIss = "$ourIssuer/")
        assertError(result, "issuer_mismatch")
    }

    @Test
    fun `a code with no iss is still a success`() {
        // RFC 9207 iss is optional, and CAS omits it entirely on error responses.
        val result = decide(code = "auth-code-xyz", returnedState = sentState, returnedIss = null)
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `iss is checked after state, so a forged issuer on a forged state still reads as CSRF`() {
        val result = decide(code = "auth-code-xyz", returnedState = "attacker-state", returnedIss = "https://attacker.example")
        assertError(result, "state_mismatch")
    }

    @Test
    fun `an error response is not rejected for its iss`() {
        // No credential is delivered on the error branch, and CAS sends no iss there at all.
        val result = decide(error = "server_error", returnedState = sentState, returnedIss = "https://attacker.example")
        assertError(result, "server_error")
    }

    private fun assertError(result: AuthResult, expectedCode: String) {
        assertTrue("Expected AuthResult.Error but was $result", result is AuthResult.Error)
        assertEquals(expectedCode, (result as AuthResult.Error).error)
    }
}
