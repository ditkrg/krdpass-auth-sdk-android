package krd.pass.auth

/**
 * Canonical, user-safe error messages shared by [KrdpassError] and [AuthResult.message]. Keep
 * these byte-identical with the iOS/Flutter/RN SDKs (guarded by AuthResultTest).
 */
internal object KrdpassMessages {
    const val CANCELLED = "Authentication was cancelled"
    const val TIMEOUT = "Authentication timed out"
    const val BUSY = "Another authentication is already in progress"
    const val PROVIDER_NOT_INSTALLED =
        "The KRDPASS app is not installed or could not be opened. Please install or update KRDPASS."
    const val STATE_MISMATCH = "State parameter mismatch: possible CSRF or response injection"
    const val ISSUER_MISMATCH = "Issuer mismatch: the response did not come from the expected authorization server"
    const val NO_CODE = "No authorization code received"
    const val INVALID_REDIRECT = "Redirect URI does not match the exact configured endpoint"
    const val STATE_REQUIRED =
        "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn()."
    const val MISSING_ID_TOKEN = "Token response did not include an id_token"
    const val NONCE_MISMATCH = "ID token nonce mismatch (possible token replay)"
}

/** Errors thrown by the signIn authentication flow. */
public sealed class KrdpassError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /**
     * The canonical wire code for this failure, byte-identical with the iOS/Flutter/RN SDKs.
     * Abstract so a new subclass that forgets its code is a compile error, not a silent null on
     * the wire. Null only on [AuthenticationFailed], when the failure had no code.
     */
    public abstract val code: String?

    // Regular (not data) classes: `data` on a Throwable derives equals/hashCode over the message
    // only, misleading for exceptions, and copy()/componentN aren't part of the error contract.
    public class ConfigurationError(override val message: String) : KrdpassError(message) {
        override val code: String = "invalid_request"
    }
    public class UserCancelled : KrdpassError(KrdpassMessages.CANCELLED) {
        override val code: String = "cancelled"
    }
    public class Timeout : KrdpassError(KrdpassMessages.TIMEOUT) {
        override val code: String = "timeout"
    }
    public class Busy : KrdpassError(KrdpassMessages.BUSY) {
        override val code: String = "busy"
    }
    public class NetworkError(override val message: String, override val cause: Throwable? = null) : KrdpassError(message, cause) {
        override val code: String = "network_error"
    }
    public class AuthenticationFailed(
        override val message: String,
        /** The structured wire code (`state_mismatch`, `nonce_mismatch`, a CAS OAuth code), when
         *  one exists. Mirrors the iOS `authenticationFailed(_, code:)` shape. */
        override val code: String? = null,
        public val installUrl: String? = null,
    ) : KrdpassError(message)
}
