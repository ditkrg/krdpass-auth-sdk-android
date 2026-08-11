package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Locks the two properties the CasException -> [KrdpassError] translation must have: the server's
 * own diagnostic survives verbatim, and retryable vs permanent failures land on different types
 * (the wrapper SDKs document `network_error` as the retryable code).
 */
class CasErrorTranslationTest {

    /** The exact shape CasClient.execute() throws: "<label> failed (<status>): <parsed error>". */
    private fun casFailure(status: Int?, parsedError: String) =
        CasException("Token refresh failed ($status): $parsedError", status)

    @Test
    fun `permanent CAS failure keeps the server diagnostic verbatim`() {
        val cas = casFailure(400, "invalid_grant: The refresh token expired")

        val translated = casErrorToKrdpassError(cas)

        assertTrue(
            "a 4xx is permanent and must not be presented as a retryable network error",
            translated is KrdpassError.AuthenticationFailed,
        )
        assertEquals(cas.message, translated.message)
        assertTrue("OAuth error code lost", translated.message!!.contains("invalid_grant"))
        assertTrue("OAuth description lost", translated.message!!.contains("The refresh token expired"))
        assertTrue("HTTP status lost", translated.message!!.contains("400"))
    }

    @Test
    fun `permanent CAS failure leaves code null so bridges keep their per-call wire code`() {
        val translated = casErrorToKrdpassError(
            casFailure(400, "invalid_grant: The refresh token expired"),
        ) as KrdpassError.AuthenticationFailed

        // `code` carries this SDK's own wire codes; a passthrough CAS code would rename the
        // documented per-call failure codes the wrapper bridges emit.
        assertNull(translated.code)
        assertNull(translated.installUrl)
    }

    @Test
    fun `retryable CAS failures become NetworkError and keep the cause`() {
        for (status in listOf(500, 502, 503, 408, 429)) {
            val cas = casFailure(status, "temporarily unavailable")

            val translated = casErrorToKrdpassError(cas)

            assertTrue(
                "status $status is transient and must be reported as retryable",
                translated is KrdpassError.NetworkError,
            )
            assertEquals(cas.message, translated.message)
            assertSame(cas, translated.cause)
        }
    }

    @Test
    fun `client errors other than 408 and 429 are permanent`() {
        for (status in listOf(400, 401, 403, 404, 409, 422)) {
            val translated = casErrorToKrdpassError(casFailure(status, "denied"))

            assertTrue(
                "status $status must not be presented as retryable",
                translated is KrdpassError.AuthenticationFailed,
            )
        }
    }

    @Test
    fun `a malformed response with no status is permanent`() {
        // Nothing was wrong with the transport, so retrying cannot help.
        val cas = CasException("Invalid token response: missing or empty access_token")

        val translated = casErrorToKrdpassError(cas)

        assertTrue(translated is KrdpassError.AuthenticationFailed)
        assertEquals("Invalid token response: missing or empty access_token", translated.message)
    }

    // A transport failure reaches translatingCasErrors as a raw IOException, not a CasException;
    // these lock the same two properties for that path.

    @Test
    fun `a transport IOException keeps its message and cause`() {
        val io = IOException("Connection refused")

        val translated = ioErrorToKrdpassError(io)

        assertEquals("Connection refused", translated.message)
        assertSame(io, translated.cause)
    }

    @Test
    fun `a transport IOException with no message falls back to a canonical one`() {
        val translated = ioErrorToKrdpassError(IOException())

        assertEquals("Network request failed", translated.message)
    }
}
