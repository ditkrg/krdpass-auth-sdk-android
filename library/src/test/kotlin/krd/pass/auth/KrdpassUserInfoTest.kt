package krd.pass.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * [KrdpassUserInfo.citizenFullName] joins the four registry name parts. The same member exists on
 * the iOS, Flutter and React Native SDKs, so the join order and the blank-part rule are asserted
 * here rather than left to each caller to rediscover.
 */
class KrdpassUserInfoTest {

    @Test
    fun `all four parts join in registry order with single spaces`() {
        assertEquals("Aram Rebaz Karwan Hawrami", info("Aram", "Rebaz", "Karwan", "Hawrami").citizenFullName)
    }

    @Test
    fun `missing parts are dropped rather than leaving a double space`() {
        assertEquals("Aram Hawrami", info("Aram", null, null, "Hawrami").citizenFullName)
    }

    @Test
    fun `empty-string parts are dropped`() {
        assertEquals("Aram Hawrami", info("Aram", "", "", "Hawrami").citizenFullName)
    }

    @Test
    fun `whitespace-only parts are dropped and surviving parts are trimmed`() {
        assertEquals("Aram Hawrami", info("  Aram ", "   ", "\t", " Hawrami").citizenFullName)
    }

    @Test
    fun `no usable part yields null rather than an empty string`() {
        assertNull(info(null, "", "  ", null).citizenFullName)
        assertNull(info(null, null, null, null).citizenFullName)
    }

    @Test
    fun `a single part is returned on its own`() {
        assertEquals("Hawrami", info(null, null, null, "Hawrami").citizenFullName)
    }

    private fun info(first: String?, second: String?, third: String?, surname: String?) =
        KrdpassUserInfo(
            sub = "user-123",
            citizenFirst = first,
            citizenSecond = second,
            citizenThird = third,
            citizenSurname = surname,
        )
}
