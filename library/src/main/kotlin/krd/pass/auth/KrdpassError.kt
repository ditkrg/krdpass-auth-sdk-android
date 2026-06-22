package krd.pass.auth

/**
 * Errors that can occur during signIn authentication flow.
 */
sealed class KrdpassError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    data class ConfigurationError(override val message: String) : KrdpassError(message)
    data class InvalidUrl(override val message: String) : KrdpassError(message)
    class UserCancelled : KrdpassError("User cancelled authentication")
    class Timeout : KrdpassError("Authentication timed out")
    class Busy : KrdpassError("Another authentication flow is in progress")
    data class NetworkError(override val message: String, override val cause: Throwable? = null) : KrdpassError(message, cause)
    data class AuthenticationFailed(override val message: String) : KrdpassError(message)
}
