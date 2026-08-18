package krd.pass.auth

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.RemoteKeySourceException
import com.nimbusds.jose.proc.BadJOSEException
import java.io.IOException
import java.text.ParseException
import kotlinx.coroutines.CancellationException

/**
 * Run a [CasClient] call, translating [CasException] and raw transport [IOException]s into the
 * public [KrdpassError] model. The message carries through verbatim: it holds the HTTP status and
 * the parsed OAuth error, the caller's only diagnostic. [KrdpassError.AuthenticationFailed.code]
 * stays null: that field carries this SDK's own wire codes, and a CAS OAuth code there would
 * rename the per-call failure codes the wrapper SDKs emit today.
 */
internal inline fun <T> translatingCasErrors(block: () -> T): T = try {
    block()
} catch (e: CasException) {
    throw casErrorToKrdpassError(e)
} catch (e: KrdpassError) {
    throw e
} catch (e: IOException) {
    throw ioErrorToKrdpassError(e)
}

/** The translation itself, separated so the mapping is unit-testable without a network round trip. */
internal fun casErrorToKrdpassError(e: CasException): KrdpassError {
    val message = e.message ?: "CAS request failed"
    return if (e.isRetryable) KrdpassError.NetworkError(message, e)
    else KrdpassError.AuthenticationFailed(message)
}

/** Separated like [casErrorToKrdpassError]: unit-testable without a real transport failure. */
internal fun ioErrorToKrdpassError(e: IOException): KrdpassError.NetworkError =
    KrdpassError.NetworkError(e.message ?: "Network request failed", e)

/**
 * Translate the verifier's exception types into the public [KrdpassError] model, with the same
 * codes the other three SDKs emit. Separate from the sign-in trust path, which reports every
 * verifier failure as `invalid_id_token`. The underlying message carries through verbatim: which
 * claim failed is the only diagnostic a caller of a verify-only API has.
 */
internal inline fun <T> translatingVerifyErrors(block: () -> T): T = try {
    block()
} catch (e: CancellationException) {
    throw e
} catch (e: Exception) {
    throw verifyErrorToKrdpassError(e)
}

/** The classification itself, separated so it is unit-testable without a JWKS round trip. */
internal fun verifyErrorToKrdpassError(e: Exception): KrdpassError = when (e) {
    // Already the public model (the missing-id_token guard): re-wrapping renames its code.
    is KrdpassError -> e
    // A subclass of JOSEException, so it must be tested before it: the JWKS could not be
    // retrieved, a transport problem that may succeed on retry.
    is RemoteKeySourceException -> verifyFailure(e, "network_error")
    is IOException -> verifyFailure(e, "network_error")
    is BadJOSEException -> verifyFailure(e, "invalid_id_token")
    is JOSEException -> verifyFailure(e, "invalid_id_token")
    is ParseException -> verifyFailure(e, "invalid_id_token")
    else -> verifyFailure(e, "verification_failed")
}

private fun verifyFailure(cause: Exception, code: String): KrdpassError.AuthenticationFailed =
    KrdpassError.AuthenticationFailed("ID token verification failed: ${cause.message}", code = code)

/** Upstream text (a provider error_description, a raw CAS body) reaches the app verbatim; cap it. */
internal fun String.bounded(max: Int = MAX_UPSTREAM_TEXT_CHARS): String =
    if (length <= max) this else take(max) + "...[truncated]"

/** Enough upstream text to diagnose with, far short of a dumped page or stack. */
internal const val MAX_UPSTREAM_TEXT_CHARS: Int = 256
