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
    fun `Error result properties are correct`() {
        val result = AuthResult.Error("test_error", "Test description")

        assertFalse(result.isSuccess)
        assertFalse(result.isCancelled)
        assertFalse(result.isTimeout)
        assertFalse(result.isBusy)
        assertTrue(result.isError)
        assertEquals("test_error", result.error)
        assertEquals("Test description", result.description)
        assertEquals("Test description", result.message)
    }

    @Test
    fun `Error result without description uses error as message`() {
        val result = AuthResult.Error("test_error")

        assertEquals("test_error", result.message)
        assertNull(result.description)
    }
}

