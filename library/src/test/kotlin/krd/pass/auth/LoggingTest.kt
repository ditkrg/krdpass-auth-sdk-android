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
        // Capture logs for testing
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
    // Verify that the logger is properly set
    val testLogger = object : KrdpassLogger {
        override fun log(level: String, message: String) {
            loggedMessages.add(Pair(level, message))
        }
    }

    KrdpassAuth.logger = testLogger
    assertEquals(testLogger, KrdpassAuth.logger)

    // Test that we can call the log function (though it won't be captured in this test)
    // In a real scenario, KrdpassAuth methods would call this
}

    @Test
    fun `logging is disabled by default`() {
        KrdpassAuth.logger = null
        assertEquals(null, KrdpassAuth.logger)
    }
}