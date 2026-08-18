package krd.pass.auth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/** An RFC 7636 PKCE code verifier and S256 challenge pair. */
public data class PkcePair(
    val codeVerifier: String,
    val codeChallenge: String,
    val method: String = "S256"
) {
    override fun toString(): String {
        return "PkcePair(codeVerifier=[REDACTED], codeChallenge=[REDACTED], method='$method')"
    }
}

/** Generates RFC 7636 PKCE pairs with cryptographically secure randomness. */
public object PkceGenerator {

    /** Bytes of entropy for verifier (32 bytes = 43 base64url characters). */
    private const val VERIFIER_BYTE_LENGTH = 32

    private val secureRandom = SecureRandom()

    public fun generate(): PkcePair {
        val codeVerifier = randomUrlSafeToken(VERIFIER_BYTE_LENGTH)
        val codeChallenge = computeChallenge(codeVerifier)

        return PkcePair(
            codeVerifier = codeVerifier,
            codeChallenge = codeChallenge
        )
    }

    public fun computeChallenge(verifier: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
        return base64UrlEncodeNoPadding(hash)
    }

    /**
     * [byteLength] bytes of SecureRandom as unpadded base64url. Shared with
     * [KrdpassAuth.generateState]: every random credential this SDK mints uses the one source.
     */
    internal fun randomUrlSafeToken(byteLength: Int): String =
        base64UrlEncodeNoPadding(ByteArray(byteLength).also(secureRandom::nextBytes))

    private fun base64UrlEncodeNoPadding(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP).replace("=", "")
    }
}

