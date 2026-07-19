package krd.pass.auth

/**
 * Canonical, user-safe error messages: the single home for the fixed-message strings shared
 * by [KrdpassError] and [AuthResult.message]. Keep these byte-identical with the iOS/Flutter/RN
 * SDKs (guarded by AuthResultTest).
 */
internal object KrdpassMessages {
    const val CANCELLED = "Authentication was cancelled"
    const val TIMEOUT = "Authentication timed out"
    const val BUSY = "Another authentication is already in progress"
    const val PROVIDER_NOT_INSTALLED =
        "The KRDPASS app is not installed or could not be opened. Please install or update KRDPASS."
    const val STATE_MISMATCH = "State parameter mismatch: possible CSRF or response injection"
    const val NO_CODE = "No authorization code received"
    const val INVALID_REDIRECT = "Redirect URI does not match configured host"
    const val STATE_REQUIRED =
        "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn()."
    const val MISSING_ID_TOKEN = "Token response did not include an id_token"
    const val NONCE_MISMATCH = "ID token nonce mismatch (possible token replay)"
}

/**
 * Errors that can occur during signIn authentication flow.
 */
public sealed class KrdpassError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    // Regular (not data) classes: `data` on a Throwable derives equals/hashCode over the message
    // only, misleading for exceptions, and copy()/componentN aren't part of the error contract.
    public class ConfigurationError(override val message: String) : KrdpassError(message)
    public class UserCancelled : KrdpassError(KrdpassMessages.CANCELLED)
    public class Timeout : KrdpassError(KrdpassMessages.TIMEOUT)
    public class Busy : KrdpassError(KrdpassMessages.BUSY)
    public class NetworkError(override val message: String, override val cause: Throwable? = null) : KrdpassError(message, cause)
    public class AuthenticationFailed(
        override val message: String,
        /** The structured wire error code (e.g. `state_mismatch`, `nonce_mismatch`, a CAS OAuth
         *  code), when one exists. Mirrors the iOS `authenticationFailed(_, code:)` shape so
         *  bridges surface typed codes instead of a generic `authentication_failed`. */
        public val code: String? = null,
        public val installUrl: String? = null,
    ) : KrdpassError(message)
}
