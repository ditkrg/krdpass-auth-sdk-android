package krd.pass.auth

import android.app.Activity
import android.content.Intent
import androidx.core.net.toUri
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Drives the canonical redirect-validation vectors against the shipped validator. The vectors are
 * the cross-SDK contract, executed by the iOS suite from the same file. The vendored resource is a
 * byte copy of krdpass-auth-samples' shared/test-vectors/redirect-validation.json; the version
 * assertion below fails if the canonical file gains vectors that were never copied across.
 */
@RunWith(RobolectricTestRunner::class)
class RedirectValidationVectorTest {

    @Test
    fun `every canonical vector matches the shipped validator`() {
        val document = loadVectors()
        val defaultConfigured = document.getString("configuredRedirectUri")
        val vectors = document.getJSONArray("vectors")

        val failures = mutableListOf<String>()
        for (i in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(i)
            val id = vector.getString("id")
            val input = vector.getString("input")
            val expected = vector.getBoolean("expected")
            // Fixed-query and IP-literal vectors register their own redirect URI.
            val configured = vector.optString("configuredRedirectUri", defaultConfigured)

            val actual = KrdpassConfig("test-client-id", configured).isValidRedirectUri(input)
            if (actual != expected) {
                failures += "$id: expected $expected but got $actual for \"$input\" " +
                    "(${vector.getString("reason")})"
            }
        }

        assertTrue(
            "redirect validation diverged from the canonical vectors:\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    /** Drives the canonical RFC 9207 issuer vectors through the real Intent-to-AuthResult path. */
    @Test
    fun `every canonical issuer vector matches the shipped decision`() {
        val document = loadVectors()
        val defaultConfigured = document.getString("configuredRedirectUri")
        val vectors = document.getJSONArray("issuerVectors")

        val failures = mutableListOf<String>()
        for (i in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(i)
            val id = vector.getString("id")
            val configured = vector.optString("configuredRedirectUri", defaultConfigured)
            val config = KrdpassConfig(
                clientId = "test-client-id",
                redirectUri = configured,
                environment = environmentNamed(vector.getString("environment")),
            )
            val intent = Intent(Intent.ACTION_VIEW, vector.getString("input").toUri())

            val result = KrdpassAuth.handleAuthorizationResult(
                Activity.RESULT_OK, intent, config, vector.getString("expectedState"),
            )
            val actual = when (result) {
                is AuthResult.Success -> "success"
                is AuthResult.Error -> result.error
                else -> result.toString()
            }
            if (actual != vector.getString("expectedResult")) {
                failures += "$id: expected ${vector.getString("expectedResult")} but got $actual " +
                    "(${vector.getString("reason")})"
            }
        }

        assertTrue(
            "issuer validation diverged from the canonical vectors:\n" + failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    /** Guards the vendored copy against silently falling behind the canonical file. */
    @Test
    fun `the vendored vector file is the expected contract version`() {
        val document = loadVectors()
        assertEquals("2.3", document.getString("version"))
        assertEquals(31, document.getJSONArray("vectors").length())
        assertEquals(9, document.getJSONArray("issuerVectors").length())
    }

    private fun environmentNamed(name: String): KrdpassEnvironment = when (name) {
        "production" -> KrdpassEnvironment.Production
        "development" -> KrdpassEnvironment.Development
        else -> error("unknown environment in vector file: $name")
    }

    private fun loadVectors(): JSONObject {
        val stream = checkNotNull(
            javaClass.classLoader?.getResourceAsStream(VECTOR_RESOURCE),
        ) { "missing test resource: $VECTOR_RESOURCE" }
        return JSONObject(stream.bufferedReader().use { it.readText() })
    }

    private companion object {
        const val VECTOR_RESOURCE = "redirect-validation.json"
    }
}
