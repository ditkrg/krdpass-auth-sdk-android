package krd.pass.auth

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.*
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

        casClient = CasClient(
            clientId = "test_client",
            baseUrl = mockWebServer.url("/").toString().removeSuffix("/")
        )
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `pushAuthorizationRequest succeeds with valid response`() = runBlocking {
        val responseJson = """{"request_uri": "urn:ietf:params:oauth:request_uri:test123", "expires_in": 300}"""

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
                .setHeader("Content-Type", "application/json")
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
        assertTrue(request.path!!.endsWith("/connect/par"))

        val requestBody = request.body.readUtf8()
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
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_BAD_REQUEST)
                .setBody("Invalid request")
        )

        casClient.pushAuthorizationRequest(
            codeChallenge = "test_challenge",
            redirectUri = "https://example.com/callback",
            scopes = listOf("openid")
        )
        // Unit return required for runBlocking block when used with expression syntax, but expected exception handles it?
        // Actually runBlocking returns a value (T). If block implies Unit, it returns Unit.
        // It's safer to just let it return Unit.
        Unit
    }

    @Test(expected = CasException::class)
    fun `pushAuthorizationRequest fails with missing request_uri`() = runBlocking {
        val responseJson = """{"expires_in": 300}"""

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
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
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
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
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
                .setHeader("Content-Type", "application/json")
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
        assertTrue(request.path!!.endsWith("/connect/token"))

        val requestBody = request.body.readUtf8()
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
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
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
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
        )

        casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )
        Unit
    }

    @Test
    fun `exchangeCodeForTokens handles minimal response`() = runBlocking {
        val responseJson = """{"access_token": "minimal_token"}"""

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(HttpURLConnection.HTTP_OK)
                .setBody(responseJson)
        )

        val result = casClient.exchangeCodeForTokens(
            code = "test_code",
            codeVerifier = "test_verifier",
            redirectUri = "https://example.com/callback"
        )

        assertEquals("minimal_token", result.accessToken)
        assertEquals("Bearer", result.tokenType) // default value
        assertEquals(3600, result.expiresIn) // default value
        assertNull(result.idToken)
        assertNull(result.refreshToken)
        assertNull(result.scope)
    }
}