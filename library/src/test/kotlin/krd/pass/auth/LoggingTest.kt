package krd.pass.auth

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class LoggingTest {

    private var loggedMessages = mutableListOf<Pair<String, String>>()

    @Before
    fun setUp() {
        KrdpassAuth.logger = object : KrdpassLogger {
            override fun log(level: String, message: String) {
                loggedMessages.add(Pair(level, message))
            }
        }
    }

    @After
    fun tearDown() {
        KrdpassAuth.logger = null
        loggedMessages.clear()
    }

    @Test
    fun `logging works when logger is set`() {
        log("DEBUG", "test message")

        assertEquals(1, loggedMessages.size)
        assertEquals("DEBUG" to "test message", loggedMessages[0])
    }

    @Test
    fun `no logger installed means nothing is emitted`() {
        // The production default: log() must be a no-op, not just a null field.
        KrdpassAuth.logger = null
        loggedMessages.clear()

        log("ERROR", "must not reach anyone")

        assertEquals(0, loggedMessages.size)
    }
}
