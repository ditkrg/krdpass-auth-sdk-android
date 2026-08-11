package krd.pass.auth

import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.net.HttpURLConnection

/**
 * The client-only sign-in pipeline must classify a CAS failure the same way every other entry
 * point does: a permanent 400 reported as `network_error` tells the caller "safe to retry" about
 * something no retry can fix. Drives the shipped [KrdpassAuth.startSignIn] with only the transport
 * redirected, so this covers the wiring, not the translation function in isolation.
 */
@RunWith(RobolectricTestRunner::class)
class SignInPipelineErrorTest {

    private lateinit var cas: MockWebServer

    private val config = KrdpassConfig(
        clientId = "test_client",
        redirectUri = "https://app.example.com/callback",
        environment = KrdpassEnvironment.Production,
    )

    @Before
    fun setUp() {
        cas = MockWebServer()
        cas.start()
        // The SDK still picks the real Production endpoints; only the transport is redirected.
        val transport = OkHttpClient.Builder().addInterceptor(toMockWebServer()).build()
        CasClient.forConfig = { clientId, environment -> CasClient(clientId, environment, transport) }
    }

    @After
    fun tearDown() {
        CasClient.forConfig = CasClient.production
        cas.close()
    }

    @Test
    fun `a permanent PAR failure is reported as AuthenticationFailed, not as retryable`() {
        cas.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_BAD_REQUEST)
                .body("""{"error":"invalid_client","error_description":"Unknown client"}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val failure = signInFailure()

        assertTrue(
            "a 400 must not reach the caller as a retryable network error, got $failure",
            failure is KrdpassError.AuthenticationFailed,
        )
        assertTrue("the OAuth diagnostic was lost", failure.message!!.contains("invalid_client"))
    }

    @Test
    fun `a transient PAR failure is still reported as a retryable NetworkError`() {
        repeat(3) {
            cas.enqueue(MockResponse.Builder().code(HttpURLConnection.HTTP_UNAVAILABLE).build())
        }

        val failure = signInFailure()

        assertTrue("a 5xx is transient and must stay retryable, got $failure", failure is KrdpassError.NetworkError)
    }

    @Test
    fun `a 200 carrying an unreadable body is permanent, not retryable`() {
        // A captive portal or misrouted proxy answers 200 with HTML: the server's answer, not a
        // transport blip.
        cas.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("<html><body>Sign in to the hotel wifi</body></html>")
                .build()
        )

        val failure = signInFailure()

        assertTrue("a garbage 200 must classify as permanent, got $failure", failure is KrdpassError.AuthenticationFailed)
    }

    /** Runs the public PAR leg of the sign-in pipeline and returns the failure it threw. */
    private fun signInFailure(): Throwable = runBlocking {
        val thrown = runCatching {
            KrdpassAuth.startSignIn(null, config, listOf(KrdpassScopes.OPENID))
        }.exceptionOrNull()
        requireNotNull(thrown) { "the pipeline delivered no result" }
    }

    /** Rewrites scheme/host/port to the mock server, preserving the path the SDK chose. */
    private fun toMockWebServer(): Interceptor = Interceptor { chain ->
        val target = cas.url("/")
        chain.proceed(
            chain.request().newBuilder()
                .url(
                    chain.request().url.newBuilder()
                        .scheme(target.scheme)
                        .host(target.host)
                        .port(target.port)
                        .build()
                )
                .build()
        )
    }
}
