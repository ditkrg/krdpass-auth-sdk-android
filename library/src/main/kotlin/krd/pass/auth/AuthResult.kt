package krd.pass.auth

/**
 * Result of a KRDPASS authentication attempt.
 */
public sealed class AuthResult {
    
    /**
     * Authentication was successful.
     * 
     * @param code The authorization code received from KRDPASS.
     * @param state The state parameter from the OAuth flow (if provided).
     */
    public data class Success(
        public val code: String,
        public val state: String? = null
    ) : AuthResult() {
        /**
         * Returns a redacted string representation that doesn't expose the authorization code.
         */
        override fun toString(): String {
            return "Success(code=[REDACTED], state=$state)"
        }
    }
    
    /**
     * User cancelled the authentication.
     */
    public data object Cancelled : AuthResult()
    
    /**
     * Authentication timed out.
     */
    public data object Timeout : AuthResult()

    /**
     * Another authentication is already in progress.
     */
    public data object Busy : AuthResult()
    
    /**
     * An error occurred during authentication.
     *
     * @param error The error code.
     * @param errorDescription Human-readable error description.
     * @param installUrl The KRDPASS install URL when [error] is `provider_not_installed`. Open
     *   this in a browser to take the user to the Play Store (or open the app if already
     *   installed). `null` for all other error codes.
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
     *
     * The [Cancelled]/[Timeout]/[Busy] objects carry no payload, so this surfaces the SDK's
     * canonical text for them, letting callers display a result without hand-writing
     * per-platform strings. [Error] returns its `errorDescription` (falling back to `error`).
     */
    public val message: String? get() = when (this) {
        is Success -> null
        Cancelled -> KrdpassMessages.CANCELLED
        Timeout -> KrdpassMessages.TIMEOUT
        Busy -> KrdpassMessages.BUSY
        is Error -> errorDescription ?: error
    }

    public val isProviderNotInstalled: Boolean get() = this is Error && this.code == AuthErrorCode.PROVIDER_NOT_INSTALLED

    /** True only for a CSRF/state-mismatch error (fail-closed rejection of an injected response). */
    public val isStateMismatch: Boolean get() = this is Error && this.code == AuthErrorCode.STATE_MISMATCH

    /**
     * Check if the result is successful.
     */
    public val isSuccess: Boolean get() = this is Success
    
    /**
     * Check if the result is a cancellation.
     */
    public val isCancelled: Boolean get() = this is Cancelled
    
    /**
     * Check if the result is a timeout.
     */
    public val isTimeout: Boolean get() = this is Timeout

    /**
     * Check if the result indicates another authentication is in progress.
     */
    public val isBusy: Boolean get() = this is Busy
    
    /**
     * Check if the result is an error.
     */
    public val isError: Boolean get() = this is Error
}

/**
 * The closed set of error codes the SDK itself produces in [AuthResult.Error.error]. The wire string
 * stays the field of record: it's marshalled byte-identically across the iOS/Flutter/RN SDKs, and an
 * OAuth provider may return an arbitrary code that [fromWire] maps to null, but this enum gives
 * callers typed, typo-safe access to the known ones (so no consumer hand-writes a magic string).
 */
public enum class AuthErrorCode(public val wire: String) {
    PROVIDER_NOT_INSTALLED("provider_not_installed"),
    STATE_MISMATCH("state_mismatch"),
    INVALID_REDIRECT("invalid_redirect"),
    NO_CODE("no_code"),
    INVALID_REQUEST("invalid_request"),
    // Emitted by the KRDPASS provider app itself when the consent session's request_uri has
    // expired; the right client reaction is "restart the flow", NOT "user cancelled".
    REQUEST_EXPIRED("request_expired"),
    LAUNCH_FAILED("launch_failed"),
    PLATFORM_ERROR("platform_error"),
    CANCELLED("cancelled");

    public companion object {
        /** The typed code for [wire], or null if unrecognized (e.g. a passthrough OAuth-provider error). */
        public fun fromWire(wire: String): AuthErrorCode? = entries.firstOrNull { it.wire == wire }
    }
}
