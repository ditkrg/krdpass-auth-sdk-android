package krd.pass.auth

/**
 * Receives diagnostic messages from the SDK. Install one via [KrdpassAuth.logger];
 * with none installed the SDK logs nothing at all, which is the production default.
 *
 * @param level one of `DEBUG`, `INFO`, `WARN`, `ERROR`.
 * @param message already redacted: tokens, authorization codes and PKCE values
 *   never reach this callback.
 */
public fun interface KrdpassLogger {
    public fun log(level: String, message: String)
}

internal fun log(level: String, message: String) {
    KrdpassAuth.logger?.log(level, message)
}
