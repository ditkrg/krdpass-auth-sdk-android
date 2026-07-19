package krd.pass.auth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * A PKCE (Proof Key for Code Exchange) code verifier and challenge pair.
 *
 * Implements RFC 7636 compliant PKCE flow with S256 challenge method.
 */
public data class PkcePair(
    /** The code verifier (43-128 characters, base64url alphabet). */
    val codeVerifier: String,

    /** The code challenge (base64url-encoded SHA256 hash of verifier). */
    val codeChallenge: String,

    /** The challenge method (always 'S256' for this implementation). */
    val method: String = "S256"
) {
    /**
     * Returns a redacted string representation that doesn't expose the code verifier.
     */
    override fun toString(): String {
        return "PkcePair(codeVerifier=[REDACTED], codeChallenge=[REDACTED], method='$method')"
    }
}

/**
 * Generates a PKCE code verifier and challenge pair.
 *
 * Uses RFC 7636 compliant S256 method with cryptographically secure
 * random number generation.
 */
public object PkceGenerator {

    /** Minimum verifier length per RFC 7636. */
    public const val MIN_VERIFIER_LENGTH: Int = 43

    /** Maximum verifier length per RFC 7636. */
    public const val MAX_VERIFIER_LENGTH: Int = 128

    /** Bytes of entropy for verifier (32 bytes = 43 base64url characters). */
    private const val VERIFIER_BYTE_LENGTH = 32

    /** Thread-safe SecureRandom instance reused for all PKCE generation. */
    private val secureRandom = SecureRandom()

    /**
     * Generates a new RFC 7636 compliant PKCE pair.
     *
     * Uses cryptographically secure random number generation.
     */
    public fun generate(): PkcePair {
        val verifierBytes = ByteArray(VERIFIER_BYTE_LENGTH).also(secureRandom::nextBytes)
        val codeVerifier = base64UrlEncodeNoPadding(verifierBytes)
        val codeChallenge = computeChallenge(codeVerifier)

        return PkcePair(
            codeVerifier = codeVerifier,
            codeChallenge = codeChallenge
        )
    }

    /**
     * Computes the S256 challenge for a given verifier.
     *
     * Useful for validation or creating pairs from existing verifiers.
     */
    public fun computeChallenge(verifier: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
        return base64UrlEncodeNoPadding(hash)
    }

    private fun base64UrlEncodeNoPadding(bytes: ByteArray): String {
        // Use Android's Base64 encoder with URL-safe flags and strip padding
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP).replace("=", "")
    }
}

