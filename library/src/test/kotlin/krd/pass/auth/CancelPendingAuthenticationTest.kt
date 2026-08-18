package krd.pass.auth

import android.os.Looper
import androidx.activity.ComponentActivity
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.net.HttpURLConnection
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * [KrdpassAuth.cancelPendingAuthentication] races the live pipeline, so it is tested against the
 * real one: a flight claimed by the public [KrdpassAuth.signIn], cancelled mid-PAR.
 */
@RunWith(RobolectricTestRunner::class)
class CancelPendingAuthenticationTest {

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
        val transport = OkHttpClient.Builder().addInterceptor(toMockWebServer()).build()
        CasClient.forConfig = { clientId, environment -> CasClient(clientId, environment, transport) }
    }

    @After
    fun tearDown() {
        // Settle anything still in flight so the singleton carries no state into other tests.
        KrdpassAuth.cancelPendingAuthentication()
        shadowOf(Looper.getMainLooper()).idle()
        CasClient.forConfig = CasClient.production
        cas.close()
    }

    @Test
    fun `cancel during PAR settles signIn as UserCancelled instead of launching KRDPASS`() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).create()
        KrdpassAuth.register(controller.get())
        controller.start().resume()
        KrdpassAuth.initialize(config)

        // A PAR that answers slowly enough for the cancel to land first.
        cas.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":600}""")
                .setHeader("Content-Type", "application/json")
                .headersDelay(500, TimeUnit.MILLISECONDS)
                .build()
        )

        var failure: Throwable? = null
        val done = CountDownLatch(1)
        KrdpassAuth.signIn(callback = object : SignInCallback {
            override fun onSuccess(tokens: KrdpassTokenResult) = done.countDown()
            override fun onFailure(error: Throwable) {
                failure = error
                done.countDown()
            }
        })

        // signIn claims the flight synchronously, before PAR: the cancel must find it.
        KrdpassAuth.cancelPendingAuthentication()

        val deadline = System.currentTimeMillis() + 5_000
        while (done.count > 0 && System.currentTimeMillis() < deadline) {
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }

        assertTrue("expected UserCancelled, got $failure", failure is KrdpassError.UserCancelled)
        controller.pause().stop().destroy()
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
