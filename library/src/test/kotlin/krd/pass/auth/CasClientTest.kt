package krd.pass.auth

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.After
import org.json.JSONException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlinx.coroutines.runBlocking
import java.net.HttpURLConnection

@RunWith(RobolectricTestRunner::class)
class CasClientTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var casClient: CasClient

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        // The shipped client aimed at the real Production endpoints; only the transport is
        // redirected, so URL selection cannot be conditional on a test-only field.
        casClient = CasClient(
            clientId = "test_client",
            environment = KrdpassEnvironment.Production,
            httpClient = OkHttpClient.Builder().addInterceptor(toMockWebServer()).build(),
        )
    }

    @After
    fun tearDown() {
        mockWebServer.close()
    }

    /** Rewrites scheme/host/port to the mock server, preserving the path the SDK chose. */
    private fun toMockWebServer(): Interceptor = Interceptor { chain ->
        val target = mockWebServer.url("/")
        val rewritten = chain.request().newBuilder()
            .url(
                chain.request().url.newBuilder()
                    .scheme(target.scheme)
                    .host(target.host)
                    .port(target.port)
                    .build()
            )
            .build()
        chain.proceed(rewritten)
    }

    @Test
    fun `pushAuthorizationRequest succeeds with valid response`() = runBlocking {
        val responseJson = """{"request_uri": "urn:ietf:params:oauth:request_uri:test123", "expires_in": 300}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.pushAuthorizationRequest(
            codeChallenge = "test_challenge",
            redirectUri = "https://example.com/callback",
            scopes = listOf("openid", "profile")
        )

        assertEquals("urn:ietf:params:oauth:request_uri:test123", result.requestUri)
        assertEquals(300, result.expiresIn)

        val request = mockWebServer.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/connect/par", request.url.encodedPath)

        val requestBody = request.body!!.utf8()
        assertTrue(requestBody.contains("client_id=test_client"))
        assertTrue(requestBody.contains("response_type=code"))
        assertTrue(requestBody.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
        assertTrue(requestBody.contains("scope=openid%20profile") || requestBody.contains("scope=openid+profile"))
        assertTrue(requestBody.contains("code_challenge=test_challenge"))
        assertTrue(requestBody.contains("code_challenge_method=S256"))
    }

    @Test(expected = CasException::class)
    fun `pushAuthorizationRequest fails with HTTP error`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_BAD_REQUEST)
                .body("Invalid request")
                .build()
        )

        casClient.pushAuthorizationRequest(
            codeChallenge = "test_challenge",
            redirectUri = "https://example.com/callback",
            scopes = listOf("openid")
        )
        Unit
    }

    @Test(expected = CasException::class)
    fun `pushAuthorizationRequest fails with missing request_uri`() = runBlocking {
        val responseJson = """{"expires_in": 300}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .build()
        )

        casClient.pushAuthorizationRequest(
            codeChallenge = "test_challenge",
            redirectUri = "https://example.com/callback",
            scopes = listOf("openid")
        )
        Unit
    }

    @Test(expected = CasException::class)
    fun `pushAuthorizationRequest fails with empty request_uri`() = runBlocking {
        val responseJson = """{"request_uri": "", "expires_in": 300}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .build()
        )

        casClient.pushAuthorizationRequest(
            codeChallenge = "test_challenge",
            redirectUri = "https://example.com/callback",
            scopes = listOf("openid")
        )
        Unit
    }

    @Test
    fun `exchangeCodeForTokens succeeds with valid response`() = runBlocking {
        val responseJson = """
        {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "test_id_token",
            "refresh_token": "test_refresh_token",
            "scope": "openid profile"
        }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )

        assertEquals("test_access_token", result.accessToken)
        assertEquals("Bearer", result.tokenType)
        assertEquals(3600, result.expiresIn)
        assertEquals("test_id_token", result.idToken)
        assertEquals("test_refresh_token", result.refreshToken)
        assertEquals("openid profile", result.scope)

        val request = mockWebServer.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/connect/token", request.url.encodedPath)

        val requestBody = request.body!!.utf8()
        assertTrue(requestBody.contains("grant_type=authorization_code"))
        assertTrue(requestBody.contains("client_id=test_client"))
        assertTrue(requestBody.contains("code=test_code"))
        assertTrue(requestBody.contains("code_verifier=test_verifier"))
        assertTrue(requestBody.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"))
    }

    @Test(expected = CasException::class)
    fun `exchangeCodeForTokens fails with missing access_token`() = runBlocking {
        val responseJson = """{"token_type": "Bearer", "expires_in": 3600}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .build()
        )

        casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )
        Unit
    }

    @Test(expected = CasException::class)
    fun `exchangeCodeForTokens fails with empty access_token`() = runBlocking {
        val responseJson = """{"access_token": "", "token_type": "Bearer", "expires_in": 3600}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .build()
        )

        casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )
        Unit
    }

    @Test
    fun `exchangeCodeForTokens does not retry on 500 - the code is single-use`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_INTERNAL_ERROR)
                .body("Server error")
                .build()
        )

        try {
            casClient.exchangeCodeForTokens(
                code = "test_code",
                codeVerifier = "test_verifier",
                redirectUri = "https://example.com/callback"
            )
            fail("Expected CasException")
        } catch (expected: CasException) {
            // A retry would replay the already-consumed authorization code.
            assertEquals(1, mockWebServer.requestCount)
        }
    }

    @Test
    fun `refreshTokens does not retry on 500 - the refresh token may be single-use`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_INTERNAL_ERROR)
                .body("Server error")
                .build()
        )

        try {
            casClient.refreshTokens(refreshToken = "test_refresh_token")
            fail("Expected CasException")
        } catch (expected: CasException) {
            // A retry would replay a rotated refresh token and can revoke the token family.
            assertEquals(1, mockWebServer.requestCount)
        }
    }

    @Test
    fun `exchangeCodeForTokens handles minimal response`() = runBlocking {
        val responseJson = """{"access_token": "minimal_token"}"""

        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(responseJson)
                .build()
        )

        val result = casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )

        assertEquals("minimal_token", result.accessToken)
        assertEquals("Bearer", result.tokenType)
        assertEquals(3600, result.expiresIn)
        assertNull(result.idToken)
        assertNull(result.refreshToken)
        assertNull(result.scope)
    }

    @Test
    fun `an unstructured error body has token-shaped runs redacted out of the exception message`() {
        // Not a credential: {"alg":"RS256"}.{"sub":"user-123"}.signature-bytes-here
        val jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.c2lnbmF0dXJlLWJ5dGVzLWhlcmU" // gitleaks:allow
        val opaque = "Atu5NnPqR7vXwZ0aBcDeFgHiJkLmNoPqRsTuVwXyZ01"
        val message = messageFor("Rejected token $jwt for $opaque, retry")

        assertFalse(message.contains(jwt))
        assertFalse(message.contains(opaque))
        assertTrue(message.contains("[REDACTED]"))
        assertTrue(message.contains("Rejected token"))
    }

    @Test
    fun `an oversized error body is truncated in the exception message`() {
        // No token shape to redact, so only the length bound can stop it.
        val message = messageFor("upstream failure ".repeat(250))

        assertTrue(message.contains("...[truncated]"))
        assertTrue("Message was ${message.length} chars", message.length < 400)
    }

    @Test
    fun `a structured OAuth error keeps its readable text`() {
        val message = messageFor(
            """{"error":"invalid_grant","error_description":"authorization code expired"}""")

        assertTrue(message.contains("invalid_grant: authorization code expired"))
    }

    @Test
    fun `a token-shaped run in a structured error_description never reaches the error message`() {
        val opaque = "Atu5NnPqR7vXwZ0aBcDeFgHiJkLmNoPqRsTuVwXyZ01"
        val message = messageFor(
            """{"error":"invalid_grant","error_description":"token $opaque was rejected"}""")

        assertFalse(message.contains(opaque))
        assertTrue(message.contains("invalid_grant"))
        assertTrue(message.contains("[REDACTED]"))
        assertFalse(krdpassMessageFor(
            """{"error":"invalid_grant","error_description":"token $opaque was rejected"}""")
            .contains(opaque))
    }

    @Test
    fun `an oversized structured error_description is truncated in the error message`() {
        val message = messageFor(
            """{"error":"invalid_grant","error_description":"${"code expired ".repeat(100)}"}""")

        assertTrue(message.contains("...[truncated]"))
        assertTrue("Message was ${message.length} chars", message.length < 400)
    }

    /** The public [KrdpassError] message an app sees for a 400 whose body is [body]. */
    private fun krdpassMessageFor(body: String): String = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_BAD_REQUEST)
                .body(body)
                .build()
        )
        try {
            casClient.exchangeCodeForTokens("test_code", "test_verifier", "https://example.com/cb")
            fail("Expected CasException")
            ""
        } catch (e: CasException) {
            casErrorToKrdpassError(e).message.orEmpty()
        }
    }

    /** The CasException message for a 400 whose body is [body]. Token exchange never retries. */
    private fun messageFor(body: String): String = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_BAD_REQUEST)
                .body(body)
                .build()
        )
        try {
            casClient.exchangeCodeForTokens("test_code", "test_verifier", "https://example.com/cb")
            fail("Expected CasException")
            ""
        } catch (e: CasException) {
            e.message.orEmpty()
        }
    }

    @Test
    fun `getUserInfo recursively converts raw JSON values`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body(
                    """
                    {
                        "sub": "user-123",
                        "roles": ["citizen", {"name": "administrator"}, null],
                        "address": {"city": "Erbil", "lines": ["line one", null]},
                        "nullable": null
                    }
                    """.trimIndent()
                )
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.getUserInfo("access-token")

        assertEquals(
            listOf("citizen", mapOf("name" to "administrator"), null),
            result.raw["roles"]
        )
        assertEquals(
            mapOf("city" to "Erbil", "lines" to listOf("line one", null)),
            result.raw["address"]
        )
        assertNull(result.raw["nullable"])

        val request = mockWebServer.takeRequest()
        assertEquals("/connect/userinfo", request.url.encodedPath)
        assertEquals("Bearer access-token", request.headers["Authorization"])
    }

    @Test
    fun `getUserInfo parses upns as a list of strings`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"sub": "user-123", "upns": ["UPN-OLD-1", "UPN-OLD-2"]}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.getUserInfo("access-token")

        assertEquals(listOf("UPN-OLD-1", "UPN-OLD-2"), result.upns)
    }

    @Test
    fun `getUserInfo defaults upns to an empty list when the claim is absent`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"sub": "user-123"}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.getUserInfo("access-token")

        assertEquals(emptyList<String>(), result.upns)
    }

    @Test
    fun `getUserInfo defaults upns to an empty list when the claim is not an array of strings`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"sub": "user-123", "upns": "not-an-array"}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.getUserInfo("access-token")

        assertEquals(emptyList<String>(), result.upns)
    }

    @Test
    fun `getUserInfo rejects a blank sub instead of returning an empty primary key`() = runBlocking {
        // sub is the primary key and must never be empty; the iOS, Flutter and RN SDKs all fail
        // this response too.
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"sub": "", "name": "Someone"}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        try {
            casClient.getUserInfo("access-token")
            fail("an empty sub must not parse")
        } catch (e: CasException) {
            // Parsing runs inside execute()'s funnel: an unusable 200 body is the same permanent
            // CasException a 4xx is, never a raw JSONException.
            assertTrue(e.message!!.contains("UserInfo request"))
            assertFalse("an unreadable body is the server's answer, not a blip", e.isRetryable)
        }
    }

    @Test
    fun `a 200 with an unreadable body fails permanently instead of throwing JSONException`() = runBlocking {
        // A captive portal or misrouted proxy answers 200 with HTML.
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("<html><body>Sign in to the hotel wifi</body></html>")
                .build()
        )

        try {
            casClient.pushAuthorizationRequest(
                codeChallenge = "test_challenge",
                redirectUri = "https://example.com/callback",
                scopes = listOf("openid"),
            )
            fail("an unreadable body must not parse")
        } catch (e: CasException) {
            assertTrue(e.message!!.contains("unreadable body"))
            assertFalse(e.isRetryable)
            assertTrue("the parse failure is kept as the cause", e.cause is JSONException)
        }
    }

    @Test
    fun `getUserInfo keeps a whitespace-only sub, matching the other three SDKs`() = runBlocking {
        mockWebServer.enqueue(
            MockResponse.Builder()
                .code(HttpURLConnection.HTTP_OK)
                .body("""{"sub": " "}""")
                .setHeader("Content-Type", "application/json")
                .build()
        )

        val result = casClient.getUserInfo("access-token")

        assertEquals(" ", result.sub)
    }
}
