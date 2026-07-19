package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Tests the fail-closed provider signing-cert pinning decision (S1). This is the
 * security-critical branch that decides whether the SDK may launch the installed
 * KRDPASS app, so every path is covered.
 */
@RunWith(RobolectricTestRunner::class)
class ProviderPinningTest {

    private val pinnedA = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    private val pinnedB = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"

    @Test
    fun `production with an empty pin set fails closed`() {
        // A misconfigured Production build must never launch unpinned.
        val error = ProviderVerifier.evaluateSigningPin(
            installedCerts = setOf(pinnedA),
            expected = emptySet(),
            isProduction = true,
        )
        assertTrue(error != null && error.contains("not configured"))
    }

    @Test
    fun `development with an empty pin set skips the check`() {
        assertNull(
            ProviderVerifier.evaluateSigningPin(
                installedCerts = setOf(pinnedA),
                expected = emptySet(),
                isProduction = false,
            ),
        )
    }

    @Test
    fun `a matching cert is allowed`() {
        assertNull(
            ProviderVerifier.evaluateSigningPin(
                installedCerts = setOf("other", pinnedA),
                expected = setOf(pinnedA),
                isProduction = true,
            ),
        )
    }

    @Test
    fun `a mismatched cert is rejected`() {
        val error = ProviderVerifier.evaluateSigningPin(
            installedCerts = setOf(pinnedB),
            expected = setOf(pinnedA),
            isProduction = true,
        )
        assertTrue(error != null && error.contains("could not be verified"))
    }

    @Test
    fun `a missing provider is rejected when a pin is configured`() {
        val error = ProviderVerifier.evaluateSigningPin(
            installedCerts = null,
            expected = setOf(pinnedA),
            isProduction = false,
        )
        assertTrue(error != null && error.contains("not installed"))
    }

    @Test
    fun `any one matching fingerprint in a multi-pin set is sufficient (rotation)`() {
        assertNull(
            ProviderVerifier.evaluateSigningPin(
                installedCerts = setOf(pinnedB),
                expected = setOf(pinnedA, pinnedB),
                isProduction = true,
            ),
        )
    }

    @Test
    fun `certSha256Hex matches assetlinks format (uppercase colon-hex of the cert bytes)`() {
        // SHA-256 of zero-length input is the well-known e3b0c442... digest.
        assertEquals(
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
            ProviderVerifier.certSha256Hex(ByteArray(0)),
        )
    }
}
