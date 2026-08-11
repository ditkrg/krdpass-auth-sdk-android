package krd.pass.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.RemoteKeySourceException
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jwt.proc.BadJWTException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.text.ParseException

/**
 * Locks [KrdpassAuth.verifyToken]'s three-code contract shared with the iOS/Flutter/RN SDKs:
 * `invalid_id_token` (signature, claims, exp), `network_error` (JWKS fetch failed, retry may
 * help), `verification_failed` (anything else). No raw Nimbus or JOSE exception may escape.
 */
class VerifyTokenErrorContractTest {

    private fun codeFor(e: Exception): String? =
        (verifyErrorToKrdpassError(e) as KrdpassError.AuthenticationFailed).code

    @Test
    fun `a failed claim check is invalid_id_token`() {
        assertEquals("invalid_id_token", codeFor(BadJWTException("JWT iss claim has value X")))
    }

    @Test
    fun `a bad signature is invalid_id_token`() {
        assertEquals("invalid_id_token", codeFor(BadJOSEException("Signed JWT rejected")))
        assertEquals("invalid_id_token", codeFor(JOSEException("bad key")))
    }

    @Test
    fun `an unparseable JWT is invalid_id_token`() {
        assertEquals("invalid_id_token", codeFor(ParseException("Invalid JWT serialization", 0)))
    }

    @Test
    fun `a JWKS retrieval failure is network_error, not invalid_id_token`() {
        // RemoteKeySourceException extends JOSEException, so the check order is what makes this a
        // transport failure rather than a rejected token.
        val e = RemoteKeySourceException("Couldn't retrieve JWKS", IOException("timeout"))

        assertEquals("network_error", codeFor(e))
    }

    @Test
    fun `a plain transport failure is network_error`() {
        assertEquals("network_error", codeFor(IOException("connection reset")))
    }

    @Test
    fun `anything else falls back to verification_failed`() {
        assertEquals("verification_failed", codeFor(IllegalStateException("unexpected")))
    }

    @Test
    fun `an already typed KrdpassError passes through so its code is not renamed`() {
        val original = KrdpassError.AuthenticationFailed(
            KrdpassMessages.MISSING_ID_TOKEN, code = "invalid_id_token")

        val translated = verifyErrorToKrdpassError(original)

        assertSame(original, translated)
        assertEquals(KrdpassMessages.MISSING_ID_TOKEN, translated.message)
    }

    @Test
    fun `the underlying reason survives verbatim`() {
        // Which claim failed is the only diagnostic a caller of a verify-only API has.
        val translated = verifyErrorToKrdpassError(
            BadJWTException("JWT audience rejected: [wrong-client]"))
                as KrdpassError.AuthenticationFailed

        assertTrue(
            "claim detail lost: ${translated.message}",
            translated.message.contains("JWT audience rejected: [wrong-client]"),
        )
    }

    @Test
    fun `no verify failure carries a nonce_mismatch or issuer_mismatch code`() {
        // Both are real codes elsewhere in the taxonomy; neither is reachable through this entry
        // point, so neither may be emitted here.
        val failures = listOf(
            BadJWTException("JWT iss claim has value X"),
            RemoteKeySourceException("Couldn't retrieve JWKS", IOException("timeout")),
            ParseException("Invalid JWT serialization", 0),
            IllegalStateException("unexpected"),
        )

        for (e in failures) {
            val code = codeFor(e)
            assertTrue(
                "unexpected code $code for ${e.javaClass.simpleName}",
                code in setOf("invalid_id_token", "network_error", "verification_failed"),
            )
        }
    }

    @Test
    fun `every translated failure is a KrdpassError so no raw Nimbus type escapes`() {
        val failures = listOf<Exception>(
            BadJWTException("claims"),
            BadJOSEException("signature"),
            JOSEException("key"),
            ParseException("parse", 0),
            RemoteKeySourceException("jwks", IOException("io")),
            IOException("io"),
            IllegalStateException("other"),
        )

        for (e in failures) {
            val translated = verifyErrorToKrdpassError(e)
            assertTrue(
                "${e.javaClass.simpleName} escaped as itself",
                translated is KrdpassError.AuthenticationFailed,
            )
            assertNull(
                "installUrl is not part of this contract",
                (translated as KrdpassError.AuthenticationFailed).installUrl,
            )
        }
    }
}
