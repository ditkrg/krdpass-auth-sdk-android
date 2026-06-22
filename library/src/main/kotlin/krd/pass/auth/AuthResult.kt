package krd.pass.auth

/**
 * Result of a KRDPass authentication attempt.
 */
sealed class AuthResult {
    
    /**
     * Authentication was successful.
     * 
     * @param code The authorization code received from KRDPass.
     * @param state The state parameter from the OAuth flow (if provided).
     */
    data class Success(
        val code: String,
        val state: String? = null
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
    data object Cancelled : AuthResult()
    
    /**
     * Authentication timed out.
     */
    data object Timeout : AuthResult()

    /**
     * Another authentication is already in progress.
     */
    data object Busy : AuthResult()
    
    /**
     * An error occurred during authentication.
     * 
     * @param error The error code.
     * @param description Human-readable error description.
     */
    data class Error(
        val error: String,
        val description: String? = null
    ) : AuthResult() {
        val message: String get() = description ?: error
    }
    
    /**
     * Check if the result is successful.
     */
    val isSuccess: Boolean get() = this is Success
    
    /**
     * Check if the result is a cancellation.
     */
    val isCancelled: Boolean get() = this is Cancelled
    
    /**
     * Check if the result is a timeout.
     */
    val isTimeout: Boolean get() = this is Timeout

    /**
     * Check if the result indicates another authentication is in progress.
     */
    val isBusy: Boolean get() = this is Busy
    
    /**
     * Check if the result is an error.
     */
    val isError: Boolean get() = this is Error
}
