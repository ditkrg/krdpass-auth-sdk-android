package krd.pass.auth

/** Result of a KRDPASS authentication attempt. */
public sealed class AuthResult {

    /** Authentication succeeded; [code] is the authorization code received from KRDPASS. */
    public data class Success(
        public val code: String,
        public val state: String? = null
    ) : AuthResult() {
        override fun toString(): String {
            return "Success(code=[REDACTED], state=$state)"
        }
    }

    /** User cancelled the authentication. */
    public data object Cancelled : AuthResult()

    /** Authentication timed out. */
    public data object Timeout : AuthResult()

    /** Another authentication is already in progress. */
    public data object Busy : AuthResult()

    /**
     * An error occurred during authentication.
     *
     * @param installUrl The KRDPASS install URL when [error] is `provider_not_installed`; open it
     *   in a browser to take the user to the Play Store. `null` for all other error codes.
     */
    public data class Error(
        public val error: String,
        public val errorDescription: String? = null,
        public val installUrl: String? = null,
    ) : AuthResult() {
        /** Typed view of [error]; null for an unrecognized (e.g. passthrough OAuth-provider) code. */
        public val code: AuthErrorCode? get() = AuthErrorCode.fromWire(error)
    }

    /**
     * A canonical, user-safe message for any non-success result, or `null` on success.
     * [Error] returns its `errorDescription`, falling back to `error`.
     */
    public val message: String? get() = when (this) {
        is Success -> null
        Cancelled -> KrdpassMessages.CANCELLED
        Timeout -> KrdpassMessages.TIMEOUT
        Busy -> KrdpassMessages.BUSY
        is Error -> errorDescription ?: error
    }

    /**
     * True when the user chose not to finish: [Cancelled], or an [Error] with the canonical code
     * `cancelled` (a deliberate Deny in KRDPASS). Branch on this rather than `result is Cancelled`,
     * which misses the deny-on-the-redirect path.
     */
    public val isCancelled: Boolean get() =
        this is Cancelled || (this is Error && error == "cancelled")
}

/**
 * A log-safe name for the outcome: shape only, never the payload. [AuthResult.message] carries
 * unbounded upstream text and Success's `code` is the authorization code; the KrdpassLogger
 * contract promises no raw content. Deliberately exhaustive: a new case must say what it logs.
 */
internal val AuthResult.logLabel: String get() = when (this) {
    is AuthResult.Success -> "success"
    AuthResult.Cancelled -> "cancelled"
    AuthResult.Timeout -> "timeout"
    AuthResult.Busy -> "busy"
    is AuthResult.Error -> "error($error)"
}

/**
 * The error codes the SDK recognizes in [AuthResult.Error.error]. The wire string stays the field
 * of record (marshalled byte-identically across the iOS/Flutter/RN SDKs); this enum gives callers
 * typed access to the known ones.
 */
public enum class AuthErrorCode(public val wire: String) {
    PROVIDER_NOT_INSTALLED("provider_not_installed"),
    STATE_MISMATCH("state_mismatch"),
    // RFC 9207: the response carried an `iss` that is not this environment's authorization server.
    ISSUER_MISMATCH("issuer_mismatch"),
    INVALID_REDIRECT("invalid_redirect"),
    NO_CODE("no_code"),
    INVALID_REQUEST("invalid_request"),
    // Emitted by the KRDPASS provider app when the consent session's request_uri has expired;
    // the right client reaction is "restart the flow", not "user cancelled".
    REQUEST_EXPIRED("request_expired"),
    LAUNCH_FAILED("launch_failed"),
    PLATFORM_ERROR("platform_error"),
    CANCELLED("cancelled");

    public companion object {
        /** The typed code for [wire], or null if unrecognized (a passthrough OAuth-provider error). */
        public fun fromWire(wire: String): AuthErrorCode? = entries.firstOrNull { it.wire == wire }
    }
}
