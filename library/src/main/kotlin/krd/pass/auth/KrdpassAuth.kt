package krd.pass.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCaller
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.net.toUri
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import java.security.MessageDigest
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import kotlinx.coroutines.*
import java.net.URL
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Logger interface for the KRDPass SDK.
 */
interface KrdpassLogger {
    fun log(level: String, message: String)
}

/**
 * Configure custom logging for the KRDPass SDK.
 */
internal fun log(level: String, message: String) {
    KrdpassAuth.logger?.log(level, message)
}

/**
 * Main SDK Singleton for Sign in with KRDPass authentication.
 *
 * **Usage:**
 * 1. Call `KrdpassAuth.initialize(config)` in your Application class or MainActivity.
 * 2. Call `KrdpassAuth.register(this)` in your Activity's `onCreate`.
 * 3. Call `KrdpassAuth.authenticate(...)` to start the flow.
 */
object KrdpassAuth {

    var logger: KrdpassLogger? = null
    private val secureRandom = SecureRandom()

    @Volatile
    var config: KrdpassConfig? = null
        private set

    // Active auth state
    private var activeLauncher: ActivityResultLauncher<Intent>? = null
    private var activeResultCallback: ((AuthResult) -> Unit)? = null
    private var activeLifecycleOwner: LifecycleOwner? = null
    
    @Volatile
    private var isAuthenticating = false
    @Volatile
    private var currentState: String? = null
    @Volatile
    private var timeoutJob: Job? = null

    // JWKS Cache (read/written from IO-dispatched coroutines; keep visibility explicit).
    @Volatile
    private var cachedJwkSource: com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext>? = null
    @Volatile
    private var jwksCacheExpiresAt: Long = 0

    /**
     * Initialize the SDK with global configuration.
     * Should be called in Application.onCreate() or MainActivity.onCreate().
     */
    fun initialize(config: KrdpassConfig) {
        validateConfig(config)
        this.config = config
        // Clear caches on config change
        cachedJwkSource = null
        jwksCacheExpiresAt = 0
        log("INFO", "KrdpassAuth initialized with Client ID: ${config.clientId}")
    }

    /**
     * Register an Activity to handle KRDPass authentication results.
     * **Must be called in Activity.onCreate()**, before the Activity is STARTED.
     *
     * @param activity The ComponentActivity that will host the auth flow.
     */
    fun register(activity: ComponentActivity) {
        register(activity as ActivityResultCaller, activity as LifecycleOwner)
    }

    /**
     * Generic register for ActivityResultCaller + LifecycleOwner.
     * Used internally or for Fragments.
     */
    fun register(caller: ActivityResultCaller, lifecycleOwner: LifecycleOwner) {
        // Register the launcher
        val launcher = caller.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            handleActivityResult(result)
        }

        // Hook lifecycle to clean up
        lifecycleOwner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) {
                // Determine if we need to restore state? 
                // Mostly likely not needed for simple flows, but good for single-top validity.
                activeLauncher = launcher
                activeLifecycleOwner = owner
            }
            
            override fun onDestroy(owner: LifecycleOwner) {
                if (activeLifecycleOwner == owner) {
                    log("INFO", "Activity destroyed, cleaning up auth launcher")
                    cancelTimeout()
                    activeLauncher = null
                    activeLifecycleOwner = null
                    activeResultCallback = null // Potential leak if callback holds context, so clear it
                    isAuthenticating = false
                }
            }
        })
        
        // Set as active immediately for this lifecycle
        activeLauncher = launcher
        activeLifecycleOwner = lifecycleOwner
        log("DEBUG", "Registered ActivityResultLauncher for lifecycle: $lifecycleOwner")
    }

    /**
     * Launch KRDPass for authentication.
     *
     * @param requestUri The request URI returned from your backend's /oauth/par endpoint.
     * @param state Optional state for validation.
     * @param timeout Timeout duration.
     * @param callback Callback for the result.
     */
    fun authenticate(
        requestUri: String,
        state: String? = null,
        timeout: kotlin.time.Duration = kotlin.time.Duration.parse("5m"),
        callback: (AuthResult) -> Unit
    ) {
        authenticateInternal(
            requestUri = requestUri,
            state = state,
            timeout = timeout,
            callback = callback,
            allowWhenAuthenticating = false
        )
    }

    private fun authenticateInternal(
        requestUri: String,
        state: String? = null,
        timeout: kotlin.time.Duration = kotlin.time.Duration.parse("5m"),
        callback: (AuthResult) -> Unit,
        allowWhenAuthenticating: Boolean
    ) {
        val launcher = activeLauncher
        val owner = activeLifecycleOwner
        
        if (launcher == null || owner == null) {
            callback(AuthResult.Error(
                error = "platform_error",
                description = "KrdpassAuth not registered. Call KrdpassAuth.register(this) in onCreate()."
            ))
            return
        }

        val currentConfig = config ?: run {
             callback(AuthResult.Error(
                error = "platform_error",
                description = "KrdpassAuth not initialized. Call KrdpassAuth.initialize(config)."
            ))
            return
        }

        if (isAuthenticating && !allowWhenAuthenticating) {
            log("WARN", "Authentication already in progress")
            callback(AuthResult.Busy)
            return
        }

        if (requestUri.isBlank()) {
            if (allowWhenAuthenticating) {
                isAuthenticating = false
            }
            callback(AuthResult.Error(
                error = "platform_error",
                description = "requestUri cannot be blank"
            ))
            return
        }

        if (timeout <= kotlin.time.Duration.ZERO) {
            if (allowWhenAuthenticating) {
                isAuthenticating = false
            }
            callback(AuthResult.Error(
                error = "platform_error",
                description = "timeout must be positive"
            ))
            return
        }

        // state is mandatory for CSRF / response-injection protection (RFC 6749 §10.12).
        // signIn() generates it internally; the backend-driven authenticate() path must
        // pass the exact state baked into the PAR request by your backend.
        if (state.isNullOrBlank()) {
            if (allowWhenAuthenticating) {
                isAuthenticating = false
            }
            callback(AuthResult.Error(
                error = "invalid_request",
                description = "state is required and cannot be blank. Pass the state returned by your backend's PAR call, or use signIn() which manages state for you."
            ))
            return
        }
        log("INFO", "Starting authentication")

        // Reset state
        cancelTimeout()
        activeResultCallback = callback
        currentState = state
        isAuthenticating = true

        // S1: verify KRDPass is installed with the expected signing cert before launching.
        val context = owner as? Context
        if (context != null) {
            val providerError = checkProviderInstalled(context, currentConfig.environment)
            if (providerError != null) {
                if (allowWhenAuthenticating) isAuthenticating = false
                activeResultCallback = null
                callback(AuthResult.Error("provider_not_installed", providerError))
                return
            }
        }

        try {
            val authUrl = buildAuthorizationUrl(currentConfig, requestUri, state)
            log("DEBUG", "Launching KRDPass Intent")

            // S1: setPackage() locks the Intent to the KRDPass provider — prevents any other
            // app from registering the same deep-link scheme and intercepting the launch.
            val intent = Intent(Intent.ACTION_VIEW, authUrl.toUri())
                .setPackage(currentConfig.environment.providerPackage)
            launcher.launch(intent)

            scheduleTimeout(owner, timeout)
            log("INFO", "Authentication flow started")
        } catch (e: Exception) {
            log("ERROR", "Failed to launch: ${e.message}")
            isAuthenticating = false
            activeResultCallback = null
            callback(AuthResult.Error("launch_failed", e.message))
        }
    }

    /**
     * Suspend version of authenticate.
     */
    suspend fun authenticate(
        requestUri: String,
        state: String? = null,
        timeout: kotlin.time.Duration = kotlin.time.Duration.parse("5m")
    ): AuthResult = suspendCancellableCoroutine { cont ->
        authenticate(requestUri, state, timeout) { result ->
            if (cont.isActive) cont.resume(result)
        }
    }

    /**
     * Sign in Direct (Client-side only).
     */
    fun signIn(
        scopes: List<String> = listOf("openid", "profile"),
        timeout: kotlin.time.Duration = kotlin.time.Duration.parse("5m"),
        callback: (Result<KrdpassTokenResult>) -> Unit
    ) {
        if (scopes.isEmpty()) {
            callback(Result.failure(KrdpassError.ConfigurationError("scopes cannot be empty")))
            return
        }
        if (timeout <= kotlin.time.Duration.ZERO) {
            callback(Result.failure(KrdpassError.ConfigurationError("timeout must be positive")))
            return
        }

        val owner = activeLifecycleOwner ?: run {
             callback(Result.failure(KrdpassError.ConfigurationError("Auth not registered with an Activity")))
             return
        }
        val currentConfig = config ?: run {
            callback(Result.failure(KrdpassError.ConfigurationError("Not initialized")))
            return
        }

        if (isAuthenticating) {
            callback(Result.failure(KrdpassError.Busy()))
            return
        }

        isAuthenticating = true

        // Use the active lifecycle scope
        owner.lifecycleScope.launch(Dispatchers.IO) {
            try {
                val pkce = generatePkcePair()
                val state = generateStateInternal()
                val nonce = generateStateInternal()

                withContext(Dispatchers.Main) { currentState = state }

                val client = CasClient(currentConfig.clientId, currentConfig.environment)
                val par = client.pushAuthorizationRequest(pkce.codeChallenge, currentConfig.redirectUri, scopes, state, nonce)

                withContext(Dispatchers.Main) {
                   authenticateInternal(
                       requestUri = par.requestUri,
                       state = state,
                       timeout = timeout,
                       callback = { result ->
                       when (result) {
                           is AuthResult.Success -> {
                               owner.lifecycleScope.launch(Dispatchers.IO) {
                                   try {
                                       val tokens = client.exchangeCodeForTokens(result.code, pkce.codeVerifier, currentConfig.redirectUri)
                                       // OIDC: validate the id_token (signature, iss, aud, exp) and bind it to our nonce.
                                       validateIdToken(tokens.idToken, currentConfig, nonce)
                                       withContext(Dispatchers.Main) { callback(Result.success(tokens)) }
                                   } catch (e: Exception) {
                                       withContext(Dispatchers.Main) {
                                           callback(Result.failure(
                                               if (e is KrdpassError) e
                                               else KrdpassError.AuthenticationFailed(e.message ?: "Token exchange failed")
                                           ))
                                       }
                                   }
                               }
                           }
                           else -> {
                               val error = when(result) {
                                   is AuthResult.Cancelled -> KrdpassError.UserCancelled()
                                   is AuthResult.Timeout -> KrdpassError.Timeout()
                                   is AuthResult.Error -> KrdpassError.AuthenticationFailed(result.error)
                                   else -> KrdpassError.Busy()
                               }
                               callback(Result.failure(error))
                           }
                       }
                   },
                   allowWhenAuthenticating = true
                   )
               }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    isAuthenticating = false
                    callback(Result.failure(KrdpassError.NetworkError(e.message ?: "Unknown network error", e)))
                }
            }
        }
    }
    
    suspend fun signIn(
        scopes: List<String> = listOf("openid", "profile"),
        timeout: kotlin.time.Duration = kotlin.time.Duration.parse("5m")
    ): KrdpassTokenResult = suspendCancellableCoroutine { cont ->
        signIn(scopes, timeout) { result ->
            result.fold(
                onSuccess = { if (cont.isActive) cont.resume(it) },
                onFailure = { if (cont.isActive) cont.resumeWithException(it) }
            )
        }
    }

    // --- Helpers & Internal Logic ---

    /**
     * Verifies the KRDPass provider app is installed with the expected signing certificate.
     * Returns an error description string on failure, or null if all checks pass.
     *
     * Checks, in order:
     *  1. Pin is configured. An empty [KrdpassEnvironment.providerSigningCertsSha256] means
     *     "no pin": in Production this fails closed (never launch unpinned — that would silently
     *     reopen the sideload attack); in Development it skips the cert check for local/debug builds.
     *  2. Package is installed (NameNotFoundException → provider_not_installed).
     *  3. Signing cert SHA-256 matches a known fingerprint (cert mismatch → provider_not_installed).
     */
    private fun checkProviderInstalled(context: Context, environment: KrdpassEnvironment): String? {
        val pm = context.packageManager
        val pkg = environment.providerPackage

        val expected = environment.providerSigningCertsSha256
        if (expected.isEmpty()) {
            // Production must always pin; an empty set is a build misconfiguration, not a valid skip.
            if (environment == KrdpassEnvironment.Production) {
                return "KRDPass installation could not be verified (provider signing pin is not configured)."
            }
            // Development: pinning is optional so emulators / locally-built debug APKs can launch.
            log("WARN", "Provider cert pinning is disabled for $environment (empty pin set).")
            return null
        }

        val actualCerts: Set<String> = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = info.signingInfo
                    ?: return "KRDPass is not installed. Download it from the Play Store."
                val sigs = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners.toList()
                            else signingInfo.signingCertificateHistory.toList()
                sigs.mapTo(mutableSetOf()) { certSha256Hex(it.toByteArray()) }
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                (info.signatures ?: emptyArray()).mapTo(mutableSetOf()) { certSha256Hex(it.toByteArray()) }
            }
        } catch (_: PackageManager.NameNotFoundException) {
            return "KRDPass is not installed. Download it from the Play Store."
        }

        if (actualCerts.intersect(expected).isEmpty()) {
            return "KRDPass installation could not be verified. Please reinstall from the Play Store."
        }

        return null
    }

    private fun certSha256Hex(der: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(der).joinToString(":") { b -> "%02X".format(b) }
    }

    private fun validateConfig(config: KrdpassConfig) {
        require(config.clientId.isNotBlank()) { "clientId cannot be blank" }
        require(config.redirectUri.isNotBlank()) { "redirectUri cannot be blank" }
        val uri = config.redirectUri.toUri()
        require(uri.scheme == "https") { "redirectUri must use HTTPS" }
        require(uri.host?.isNotBlank() == true) { "redirectUri must have a valid host" }
    }

    internal fun buildAuthorizationUrl(config: KrdpassConfig, requestUri: String, state: String?): String {
        val builder = config.environment.authUrl.toUri().buildUpon()
            .appendQueryParameter("client_id", config.clientId)
            .appendQueryParameter("request_uri", requestUri)
            .appendQueryParameter("redirect_uri", config.redirectUri)
        state?.let { builder.appendQueryParameter("state", it) }
        return builder.build().toString()
    }
    
    fun buildAuthorizationUrl(requestUri: String, state: String? = null): String {
        val currentConfig = config ?: throw IllegalStateException("Not initialized")
        return buildAuthorizationUrl(currentConfig, requestUri, state)
    }

    private fun handleActivityResult(result: ActivityResult) {
        val callback = activeResultCallback ?: return
        val currentConfig = config ?: return
        
        if (result.resultCode == Activity.RESULT_CANCELED) {
             complete(AuthResult.Cancelled)
             return
        }
        
        val data = result.data
        if (result.resultCode == Activity.RESULT_OK && data != null && data.data != null) {
            val uri = data.data!!
            
            if (!currentConfig.isValidRedirectUri(uri)) {
                complete(AuthResult.Error("invalid_redirect", "Redirect URI does not match configured host"))
                return
            }
            
            val code = uri.getQueryParameter("code")
            val state = uri.getQueryParameter("state")
            val error = uri.getQueryParameter("error")

            if (code != null) {
                // Fail closed: the returned state must be present AND equal to the
                // state we sent. A missing or mismatched state is rejected.
                val expectedState = currentState
                if (expectedState.isNullOrBlank() || state.isNullOrBlank() || expectedState != state) {
                    complete(AuthResult.Error("state_mismatch", "State missing or does not match the request (possible CSRF / response injection)"))
                } else {
                    complete(AuthResult.Success(code, state))
                }
            } else if (error != null) {
                val canonicalError = when (error) {
                    "access_denied", "user_cancelled", "login_required", "consent_denied" -> "cancelled"
                    else -> error
                }
                complete(AuthResult.Error(canonicalError, uri.getQueryParameter("error_description")))
            } else {
                complete(AuthResult.Error("no_code", "No code received"))
            }
        } else {
            complete(AuthResult.Error("platform_error", "Result not OK or no data"))
        }
    }

    private fun complete(result: AuthResult) {
        cancelTimeout()
        isAuthenticating = false
        currentState = null
        activeResultCallback?.invoke(result)
        activeResultCallback = null
    }

    /**
     * Cancel any in-flight authentication (authenticate/signIn) flow.
     *
     * Useful when the user returns to your app without completing the flow in
     * KRDPass (app-switch back). After cancellation, a new flow can start.
     */
    fun cancel() {
        if (!isAuthenticating) return
        val owner = activeLifecycleOwner
        if (owner != null) {
            owner.lifecycleScope.launch(Dispatchers.Main) {
                if (isAuthenticating) complete(AuthResult.Cancelled)
            }
        } else {
            complete(AuthResult.Cancelled)
        }
    }

    /**
     * Force-timeout any in-flight authentication (authenticate/signIn) flow.
     */
    fun timeout() {
        if (!isAuthenticating) return
        val owner = activeLifecycleOwner
        if (owner != null) {
            owner.lifecycleScope.launch(Dispatchers.Main) {
                if (isAuthenticating) complete(AuthResult.Timeout)
            }
        } else {
            complete(AuthResult.Timeout)
        }
    }

    private fun scheduleTimeout(owner: LifecycleOwner, timeout: kotlin.time.Duration) {
        cancelTimeout()
        timeoutJob = owner.lifecycleScope.launch(Dispatchers.Main) {
            delay(timeout)
            if (isAuthenticating) {
               log("WARN", "Auth timed out")
               complete(AuthResult.Timeout)
            }
        }
    }
    
    private fun cancelTimeout() {
        timeoutJob?.cancel()
        timeoutJob = null
    }

    fun generatePkcePair(): PkcePair = PkceGenerator.generate()

    fun generateState(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP).replace("=", "")
    }
    
    private fun generateStateInternal(): String = generateState()
    
    // --- Public Utility Methods (Stateless) ---
    
    suspend fun getUserInfo(accessToken: String): KrdpassUserInfo = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).getUserInfo(accessToken)
    }

    suspend fun refreshTokens(refreshToken: String, scope: String? = null): KrdpassTokenResult = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).refreshTokens(refreshToken, scope)
    }

    suspend fun revokeToken(token: String, hint: String? = null) = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).revokeToken(token, hint)
    }

    /**
     * Validate the OIDC ID token returned by the client-only [signIn] flow:
     * signature (JWKS), issuer, audience (== clientId), expiry, and nonce binding.
     * @throws KrdpassError.AuthenticationFailed if any check fails.
     */
    private fun validateIdToken(idToken: String?, config: KrdpassConfig, expectedNonce: String) {
        if (idToken.isNullOrBlank()) {
            throw KrdpassError.AuthenticationFailed("Token response did not include an id_token")
        }
        val claims = try {
            verifyTokenInternal(
                token = idToken,
                jwksUrl = config.environment.jwksEndpoint,
                issuer = config.environment.authServerUrl,
                audience = config.clientId,
                clockSkewSeconds = 60
            )
        } catch (e: Exception) {
            throw KrdpassError.AuthenticationFailed("ID token validation failed: ${e.message}")
        }
        val returnedNonce = claims["nonce"] as? String
        if (returnedNonce.isNullOrBlank() || returnedNonce != expectedNonce) {
            throw KrdpassError.AuthenticationFailed("ID token nonce mismatch (possible token replay)")
        }
    }

    fun verifyToken(
        token: String,
        issuer: String? = null,
        audience: String? = null,
        clockSkewSeconds: Long = 60
    ): Map<String, Any?> {
        val c = config ?: throw IllegalStateException("Not initialized")
        val jwksUrl = c.environment.jwksEndpoint
        return verifyTokenInternal(token, jwksUrl, issuer, audience, clockSkewSeconds)
    }
    
    // Internal verification helper to keep main code clean
    private fun verifyTokenInternal(
        token: String,
        jwksUrl: String,
        issuer: String?,
        audience: String?,
        clockSkewSeconds: Long
    ): Map<String, Any?> {
        val source = getJwkSource(jwksUrl)
        val selector = JWSVerificationKeySelector(JWSAlgorithm.Family.RSA, source)
        val processor = DefaultJWTProcessor<SecurityContext>().apply { jwsKeySelector = selector }

        val requiredClaims = JWTClaimsSet.Builder().apply {
            if (!issuer.isNullOrBlank()) issuer(issuer)
            if (!audience.isNullOrBlank()) audience(audience)
        }.build()

        // Always require exp so a token with no expiry can never be accepted as non-expiring.
        val requiredClaimNames = mutableSetOf("exp").apply {
            if (!issuer.isNullOrBlank()) add("iss")
            if (!audience.isNullOrBlank()) add("aud")
        }

        val verifier: JWTClaimsSetVerifier<SecurityContext> =
            DefaultJWTClaimsVerifier(requiredClaims, requiredClaimNames)
        processor.jwtClaimsSetVerifier = verifier

        val claims = processor.process(token, null)

        val now = System.currentTimeMillis() / 1000
        claims.expirationTime?.let { exp ->
            if (now - clockSkewSeconds > exp.time / 1000) {
                throw Exception("Token expired")
            }
        }
        claims.notBeforeTime?.let { nbf ->
            if (now + clockSkewSeconds < nbf.time / 1000) {
                throw Exception("Token not yet valid")
            }
        }
        claims.issueTime?.let { iat ->
            if (now + clockSkewSeconds < iat.time / 1000) {
                throw Exception("Token used before issued")
            }
        }

        return claims.claims
    }
    
    /**
     * Decode a JWT's claims **without verifying its signature**.
     *
     * ⚠️ SECURITY: the returned claims are NOT authenticated and MUST NOT drive any
     * trust or authorization decision. Always [verifyToken] first; this is only for
     * cosmetic display of an already-verified token.
     *
     * @throws IllegalArgumentException if [token] is not a parseable JWT.
     */
    fun decodeTokenUnverified(token: String): Map<String, Any?> {
        return try {
            com.nimbusds.jwt.JWTParser.parse(token).jwtClaimsSet.claims
        } catch (e: Exception) {
            throw IllegalArgumentException("Not a valid JWT", e)
        }
    }

    private fun getJwkSource(url: String): com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext> {
        val now = System.currentTimeMillis()
        if (cachedJwkSource != null && now < jwksCacheExpiresAt) {
            return cachedJwkSource!!
        }
        val newSource = JWKSourceBuilder.create<SecurityContext>(URL(url)).retrying(true).build()
        cachedJwkSource = newSource
        jwksCacheExpiresAt = now + 60 * 60 * 1000 // 1 hour TTL
        return newSource
    }
}
