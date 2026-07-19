package krd.pass.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Logger interface for the KRDPASS SDK.
 */
public interface KrdpassLogger {
    public fun log(level: String, message: String)
}

/**
 * Configure custom logging for the KRDPASS SDK.
 */
internal fun log(level: String, message: String) {
    KrdpassAuth.logger?.log(level, message)
}

/**
 * Main SDK Singleton for Sign in with KRDPASS authentication.
 *
 * **Usage:**
 * 1. Call `KrdpassAuth.initialize(config)` in your Application class or MainActivity.
 * 2. Call `KrdpassAuth.register(this)` in your Activity's `onCreate`.
 * 3. Start a flow: `KrdpassAuth.signIn(...)` (client-only PKCE) or `KrdpassAuth.authenticate(...)`
 *    (backend-mediated, with a request URI from your server's `/oauth/par`).
 */
public object KrdpassAuth {

    private const val NOT_REGISTERED =
        "KrdpassAuth not registered. Call KrdpassAuth.register(this) in onCreate()."

    /** CSRF `state` / OIDC `nonce` entropy: 32 bytes (256 bits) of SecureRandom. */
    private const val STATE_ENTROPY_BYTES = 32

    public var logger: KrdpassLogger? = null
    private val secureRandom = SecureRandom()

    // Process-scoped Main scope for the signIn pipeline. Deliberately NOT the launching owner's
    // lifecycleScope: a configuration change destroys that scope, which would kill the pipeline
    // mid-flow and silently drop the re-adopted flight's result (the flow itself survives
    // rotation (see the onResume re-adoption in register()). The flight timeout guarantees the
    // coroutine always terminates, so a process scope cannot leak it.
    private val sdkScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    @Volatile
    public var config: KrdpassConfig? = null
        private set

    // Active auth state
    // @Volatile: written on Main (register/onResume/onDestroy) but read on the CALLER thread by the
    // off-Main authenticate() path, so the writes must be published (matches config/appContext).
    @Volatile
    private var activeLauncher: ActivityResultLauncher<Intent>? = null
    @Volatile
    private var activeLifecycleOwner: LifecycleOwner? = null
    // Application context captured at register(), used for the S1 provider cert-pin check.
    // Holding the *application* context in a process singleton is leak-safe.
    @Volatile
    private var appContext: Context? = null

    /**
     * The single in-flight flow's state, swapped atomically. "A flow is in flight" is exactly
     * `inFlight.get() != null`, so there's no separate boolean to keep in sync: claiming the slot
     * (compareAndSet null->holder) publishes the callback + expectedState + launchOwner together with
     * no half-built window, and [complete] detaches the whole holder in one getAndSet, so a
     * re-entrant authenticate()/signIn() from within the callback is safe, and there is exactly one
     * release path.
     *
     * Flight lifecycle (every arrow ends in [complete], the ONLY release):
     * ```
     *  CLAIMED   beginLaunch: inFlight.compareAndSet(null -> flight); timeout scheduled pre-launch
     *     |
     *  LAUNCHED  launcher.launch(intent): KRDPASS is now in the foreground
     *     |- result returns        -> handleActivityResult -> complete(decideAuthResult(...))
     *     |- timeout fires         -> scheduleTimeout body (=== flight guard) -> complete(Timeout)
     *     |- external cancel       -> cancelPendingAuthentication -> finishExternally
     *     |                          (main hop + === flight guard) -> complete(Cancelled|Timeout)
     *     |- host REALLY destroyed -> onDestroy (not isChangingConfigurations) -> complete(Cancelled)
     *     `- host RECREATING       -> onDestroy skips; next onResume RE-ADOPTS: re-points
     *                                launchOwner + reschedules the REMAINING deadline (or times
     *                                out immediately if already past); flow stays LAUNCHED
     *  RELEASED  complete(): inFlight.getAndSet(null), timeout cancelled, callback invoked once
     * ```
     */
    private class InFlight(
        val callback: (AuthResult) -> Unit,
        val expectedState: String,
        // var: a configuration change destroys the launching host and a recreated one re-adopts
        // the flight in onResume (see register()).
        @Volatile
        var launchOwner: LifecycleOwner,
        timeout: kotlin.time.Duration,
    ) {
        // The original timeout is a caller-specified budget, not a per-launch grant: re-adoption
        // schedules the REMAINING time, so repeatedly rotating the device can't keep extending it.
        val deadline: kotlin.time.ComparableTimeMark = kotlin.time.TimeSource.Monotonic.markNow() + timeout
        @Volatile
        var timeoutJob: Job? = null
    }
    private val inFlight = AtomicReference<InFlight?>(null)

    /**
     * Initialize the SDK with global configuration.
     * Should be called in Application.onCreate() or MainActivity.onCreate().
     */
    @JvmStatic
    public fun initialize(config: KrdpassConfig) {
        validateConfig(config)
        this.config = config
        // Clear the JWKS cache on config change (the environment may have changed).
        TokenVerifier.clearCache()
        log("INFO", "KrdpassAuth initialized with Client ID: ${config.clientId}")
    }

    /**
     * Register an Activity to handle KRDPASS authentication results.
     * **Must be called in Activity.onCreate()**, before the Activity is STARTED.
     *
     * @param activity The ComponentActivity that will host the auth flow.
     */
    @JvmStatic
    public fun register(activity: ComponentActivity) {
        register(activity as ActivityResultCaller, activity as LifecycleOwner)
    }

    /**
     * Generic register for ActivityResultCaller + LifecycleOwner.
     * Used internally or for Fragments.
     *
     * Note: config-change survival (the onResume flight re-adoption) detects recreation via
     * [Activity.isChangingConfigurations], so it only applies to Activity owners: a Fragment
     * host's in-flight flow is still cancelled on rotation.
     */
    @JvmStatic
    public fun register(caller: ActivityResultCaller, lifecycleOwner: LifecycleOwner) {
        // Capture an application Context (the caller/owner is a ComponentActivity in the
        // common path) so the S1 cert-pin check works even if the owner is a Fragment.
        appContext = appContext
            ?: (caller as? Context)?.applicationContext
            ?: (lifecycleOwner as? Context)?.applicationContext

        // Register the launcher
        val launcher = caller.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            handleActivityResult(result)
        }

        // Hook lifecycle to clean up
        lifecycleOwner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) {
                // Re-point the active launcher/owner to the most recently resumed host.
                activeLauncher = launcher
                activeLifecycleOwner = owner
                // Re-adopt a flight orphaned by a configuration change: the old host's onDestroy
                // kept it alive but its lifecycleScope (and timeout job) died with the host, so
                // re-point the owner and reschedule. The dead job's isActive==false is the marker.
                inFlight.get()?.let { flight ->
                    if (flight.launchOwner !== owner && flight.timeoutJob?.isActive != true) {
                        // Belt-and-braces: a cancelled job can be momentarily "not active yet not
                        // done"; an explicit cancel guarantees the old job can never fire after
                        // the new one is installed. (Idempotent: it is already dead or dying.)
                        flight.timeoutJob?.cancel()
                        flight.launchOwner = owner
                        val remaining = flight.deadline - kotlin.time.TimeSource.Monotonic.markNow()
                        if (remaining.isPositive()) {
                            flight.timeoutJob = scheduleTimeout(flight, owner, remaining)
                        } else {
                            log("WARN", "Auth timed out")
                            complete(AuthResult.Timeout)
                        }
                    }
                }
            }

            override fun onDestroy(owner: LifecycleOwner) {
                // If the host that LAUNCHED the in-flight flow is destroyed FOR REAL, release the
                // slot and deliver Cancelled, even if another host has since become active.
                // Otherwise the slot could stay claimed forever and every future authenticate()
                // would return Busy. A configuration change (rotation, fold, dark-mode) is NOT a
                // real destroy: the recreated host re-registers, its launcher receives the
                // provider's result via the ActivityResultRegistry, and onResume re-adopts the
                // flight: cancelling here would drop a perfectly good in-flight authentication.
                if (inFlight.get()?.launchOwner == owner &&
                    (owner as? Activity)?.isChangingConfigurations != true
                ) {
                    log("INFO", "Launching activity destroyed mid-flow; cancelling")
                    complete(AuthResult.Cancelled)
                }
                if (activeLifecycleOwner == owner) {
                    log("INFO", "Activity destroyed, cleaning up auth launcher")
                    activeLauncher = null
                    activeLifecycleOwner = null
                }
            }
        })
        
        // Set as active immediately for this lifecycle
        activeLauncher = launcher
        activeLifecycleOwner = lifecycleOwner
        log("DEBUG", "Registered ActivityResultLauncher for lifecycle: $lifecycleOwner")
    }

    /**
     * Launch KRDPASS for authentication.
     *
     * @param requestUri The request URI returned from your backend's /oauth/par endpoint.
     * @param state Required. The state your backend's PAR call returned; the SDK fails closed
     *   (invalid_request) when it is null or blank: CSRF validation cannot be skipped.
     * @param timeout Timeout duration.
     * @param callback Callback for the result.
     */
    @JvmStatic
    public fun authenticate(
        requestUri: String,
        state: String?,
        timeout: kotlin.time.Duration = 5.minutes,
        callback: (AuthResult) -> Unit
    ) {
        val owner = activeLifecycleOwner
        if (activeLauncher == null || owner == null) {
            callback(AuthResult.Error("platform_error", NOT_REGISTERED))
            return
        }
        val currentConfig = config ?: run {
            callback(AuthResult.Error("platform_error",
                "KrdpassAuth not initialized. Call KrdpassAuth.initialize(config)."))
            return
        }
        if (timeout <= kotlin.time.Duration.ZERO) {
            callback(AuthResult.Error("platform_error", "timeout must be positive"))
            return
        }
        log("INFO", "Starting authentication")
        // startAuthentication owns arg/state validation + cert-pin + intent build (shared with the
        // RN binding); this adapter only owns the Activity launcher + lifecycle + timeout.
        val context = appContext ?: (owner as? Context)
        beginLaunch(
            startAuthentication(context, currentConfig, requestUri, state ?: ""),
            expectedState = state ?: "",
            timeout = timeout,
            callback = callback,
        )
    }

    /**
     * Adapter: launch a prepared [AuthLaunch] via the registered Activity launcher, wiring the
     * in-flight callback + state + timeout. The Activity-only path; all decision logic lives in the
     * stateless [startAuthentication]/[handleAuthorizationResult].
     */
    private fun beginLaunch(
        launch: AuthLaunch,
        expectedState: String,
        timeout: kotlin.time.Duration,
        callback: (AuthResult) -> Unit,
    ) {
        when (launch) {
            // Nothing is claimed on the pre-launch failure paths, so deliver directly.
            is AuthLaunch.Failure -> callback(launch.error)
            is AuthLaunch.Ready -> {
                val launcher = activeLauncher
                val owner = activeLifecycleOwner
                if (launcher == null || owner == null) {
                    callback(AuthResult.Error("platform_error", NOT_REGISTERED))
                    return
                }
                // Atomically claim the single in-flight slot; reject concurrent callers as Busy.
                val flight = InFlight(callback, expectedState, owner, timeout)
                if (!inFlight.compareAndSet(null, flight)) {
                    log("WARN", "Authentication already in progress")
                    callback(AuthResult.Busy)
                    return
                }
                // Schedule the timeout BEFORE launching: launcher.launch() starts the provider (an
                // app-switch, slow and preemption-prone), and a cancel()/onDestroy in that window
                // must find a real timeoutJob to cancel, not a null. delay() means it can't fire
                // during the launch, and if launch throws, complete() cancels the now-real job.
                flight.timeoutJob = scheduleTimeout(flight, owner, timeout)
                try {
                    launcher.launch(launch.intent)
                    log("INFO", "Authentication flow started")
                } catch (e: Exception) {
                    log("ERROR", "Failed to launch: ${e.message}")
                    complete(AuthResult.Error("launch_failed", e.message))
                }
            }
        }
    }

    /** Suspend bridge over the callback-based [beginLaunch], so signIn() can read linearly. */
    private suspend fun awaitLaunch(
        launch: AuthLaunch,
        expectedState: String,
        timeout: kotlin.time.Duration,
    ): AuthResult = suspendCancellableCoroutine { cont ->
        beginLaunch(launch, expectedState, timeout) { if (cont.isActive) cont.resume(it) }
    }

    /**
     * Bound a caller-requested [timeout] by the PAR request_uri's lifetime: the consent session
     * dies with the request_uri, don't wait past it.
     */
    internal fun boundToParExpiry(timeout: kotlin.time.Duration, parExpiresInSeconds: Int): kotlin.time.Duration =
        minOf(timeout, parExpiresInSeconds.seconds)

    /** Map a non-success [AuthResult] to the typed [KrdpassError] used by the signIn() API. */
    private fun authResultToError(result: AuthResult): KrdpassError = when (result) {
        is AuthResult.Cancelled -> KrdpassError.UserCancelled()
        is AuthResult.Timeout -> KrdpassError.Timeout()
        is AuthResult.Busy -> KrdpassError.Busy()
        is AuthResult.Error -> KrdpassError.AuthenticationFailed(
            result.message ?: result.error, code = result.error, installUrl = result.installUrl)
        // Callers (signIn/finishSignIn) handle Success above and only route failures here.
        is AuthResult.Success -> error("authResultToError must not be called with Success")
    }

    /**
     * Suspend version of authenticate.
     */
    @JvmStatic
    public suspend fun authenticate(
        requestUri: String,
        state: String?,
        timeout: kotlin.time.Duration = 5.minutes
    ): AuthResult = suspendCancellableCoroutine { cont ->
        authenticate(requestUri, state, timeout) { result ->
            if (cont.isActive) cont.resume(result)
        }
    }

    /**
     * Sign in Direct (Client-side only).
     */
    @JvmStatic
    public fun signIn(
        scopes: List<String> = listOf("openid", "profile"),
        timeout: kotlin.time.Duration = 5.minutes,
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

        val context = appContext ?: (owner as? Context)

        // PKCE + PAR + intent build + launch + exchange all live in the stateless API (shared with the
        // RN binding); this adapter only supplies the Activity scope. beginLaunch (via awaitLaunch)
        // claims the single in-flight slot and complete() is the sole release, so this catch only
        // delivers the failure and never touches slot state (which is what fixes the stale
        // double-release: a post-result exchange failure must not re-release a freed/re-claimed slot).
        // sdkScope, not owner.lifecycleScope: the pipeline must outlive a configuration change so
        // the re-adopted flight's result still reaches [callback] (see the onResume re-adoption).
        sdkScope.launch {
            try {
                val (launch, pending) = startSignIn(context, currentConfig, scopes)
                val boundedTimeout = boundToParExpiry(timeout, pending.parExpiresInSeconds)
                when (val result = awaitLaunch(launch, pending.state, boundedTimeout)) {
                    is AuthResult.Success ->
                        callback(Result.success(
                            exchangeAndValidate(result.code, pending.codeVerifier, pending.nonce, currentConfig)))
                    else -> callback(Result.failure(authResultToError(result)))
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Structured-concurrency cancellation must propagate, not masquerade as a
                // NetworkError delivered to the callback.
                throw e
            } catch (e: Exception) {
                callback(Result.failure(
                    if (e is KrdpassError) e
                    else KrdpassError.NetworkError(e.message ?: "Unknown network error", e)))
            }
        }
    }
    
    @JvmStatic
    public suspend fun signIn(
        scopes: List<String> = listOf("openid", "profile"),
        timeout: kotlin.time.Duration = 5.minutes
    ): KrdpassTokenResult = suspendCancellableCoroutine { cont ->
        signIn(scopes, timeout) { result ->
            result.fold(
                onSuccess = { if (cont.isActive) cont.resume(it) },
                onFailure = { if (cont.isActive) cont.resumeWithException(it) }
            )
        }
    }

    // --- Stateless, launch-decoupled API ----------------------------------------------------
    // The core decides + builds; the host launches the returned Intent and delivers the result
    // back. Holds NO per-flow state, no launcher, no LifecycleOwner, so any host (Expo/RN, a
    // Service, Compose) reuses the full security flow. register()/authenticate()/signIn() below are
    // a thin Activity convenience layer over these. Mirrors the iOS core (openURL + handle()).

    /** Outcome of preparing a provider launch. */
    public sealed class AuthLaunch {
        /** Host must `startActivityForResult` this, then call [handleAuthorizationResult]. */
        public data class Ready(public val intent: Intent) : AuthLaunch()
        /** Pre-launch failure (provider not installed, bad args). Nothing was launched. */
        public data class Failure(public val error: AuthResult.Error) : AuthLaunch()
    }

    /** Opaque in-flight carrier for a client-mode (PKCE) sign-in. Host-held, memory only. */
    public class SignInPending internal constructor(
        internal val codeVerifier: String,
        internal val state: String,
        internal val nonce: String,
        internal val parExpiresInSeconds: Int,
    ) {
        override fun toString(): String = "SignInPending(REDACTED)"
    }

    /**
     * Prepare a backend-driven (server mode) authorization launch: arg validation, provider
     * cert-pin check, and the `setPackage()`-locked Intent. Does not launch and holds no state.
     * The caller launches [AuthLaunch.Ready.intent] and passes [state] back to
     * [handleAuthorizationResult]. [context] may be null (rare: no app context); the cert-pin
     * policy then fails closed when a pin is configured.
     */
    @JvmStatic
    public fun startAuthentication(
        context: Context?,
        config: KrdpassConfig,
        requestUri: String,
        state: String,
    ): AuthLaunch {
        if (requestUri.isBlank()) {
            return AuthLaunch.Failure(AuthResult.Error("platform_error", "requestUri cannot be blank"))
        }
        if (state.isBlank()) {
            return AuthLaunch.Failure(AuthResult.Error("invalid_request", KrdpassMessages.STATE_REQUIRED))
        }
        val providerError = if (context != null) {
            ProviderVerifier.checkInstalled(context, config.environment)
        } else if (config.environment.providerSigningCertsSha256.isNotEmpty()) {
            "KRDPASS installation could not be verified (no Context available to check the provider signature)."
        } else {
            null
        }
        if (providerError != null) return AuthLaunch.Failure(AuthResult.Error("provider_not_installed", providerError, installUrl = config.environment.installUrl))

        val authUrl = buildAuthorizationUrl(config, requestUri, state)
        val intent = Intent(Intent.ACTION_VIEW, authUrl.toUri()).setPackage(config.environment.providerPackage)
        return AuthLaunch.Ready(intent)
    }

    /**
     * Pure result policy for a launch started by [startAuthentication]/[startSignIn]: runs the
     * fail-closed [decideAuthResult] (CSRF/redirect/error canonicalization). [expectedState] is the
     * state the host launched with.
     */
    @JvmStatic
    public fun handleAuthorizationResult(
        resultCode: Int,
        data: Intent?,
        config: KrdpassConfig,
        expectedState: String,
    ): AuthResult {
        val uri = data?.data
        return decideAuthResult(
            resultCode = resultCode,
            hasUriData = uri != null,
            redirectValid = uri == null || config.isValidRedirectUri(uri),
            code = uri?.getQueryParameter("code"),
            returnedState = uri?.getQueryParameter("state"),
            error = uri?.getQueryParameter("error"),
            errorDescription = uri?.getQueryParameter("error_description"),
            expectedState = expectedState,
        )
    }

    /**
     * Prepare a client-mode (PKCE) sign-in: PKCE + PAR + the launch Intent. Suspend (PAR is
     * network). Returns the launch and an opaque [SignInPending] the host passes back to
     * [finishSignIn].
     */
    @JvmStatic
    public suspend fun startSignIn(
        context: Context?,
        config: KrdpassConfig,
        scopes: List<String> = listOf("openid", "profile"),
    ): Pair<AuthLaunch, SignInPending> = withContext(Dispatchers.IO) {
        val pkce = generatePkcePair()
        val state = generateState()
        val nonce = generateState()
        val par = CasClient(config.clientId, config.environment)
            .pushAuthorizationRequest(pkce.codeChallenge, config.redirectUri, scopes, state, nonce)
        val launch = startAuthentication(context, config, par.requestUri, state)
        launch to SignInPending(pkce.codeVerifier, state, nonce, par.expiresIn)
    }

    /**
     * Finish a client-mode sign-in: apply the result policy, exchange the code, and validate the
     * id_token (nonce binding). Suspend, runs on the caller's scope. Throws [KrdpassError].
     */
    @JvmStatic
    public suspend fun finishSignIn(
        resultCode: Int,
        data: Intent?,
        config: KrdpassConfig,
        pending: SignInPending,
    ): KrdpassTokenResult = withContext(Dispatchers.IO) {
        when (val result = handleAuthorizationResult(resultCode, data, config, pending.state)) {
            is AuthResult.Success -> exchangeAndValidate(result.code, pending.codeVerifier, pending.nonce, config)
            else -> throw authResultToError(result)
        }
    }

    /** Shared code-exchange + id_token (nonce) validation used by both signIn() and finishSignIn(). */
    private suspend fun exchangeAndValidate(
        code: String,
        codeVerifier: String,
        nonce: String,
        config: KrdpassConfig,
    ): KrdpassTokenResult = withContext(Dispatchers.IO) {
        val tokens = CasClient(config.clientId, config.environment)
            .exchangeCodeForTokens(code, codeVerifier, config.redirectUri)
        TokenVerifier.validateIdToken(config.environment, config.clientId, tokens.idToken, nonce)
        tokens
    }

    // --- Helpers & Internal Logic ---

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

    private fun handleActivityResult(result: ActivityResult) {
        val flight = inFlight.get() ?: return
        val currentConfig = config ?: return
        complete(handleAuthorizationResult(result.resultCode, result.data, currentConfig, flight.expectedState))
    }

    /**
     * Pure auth-result decision, separated from the Android [ActivityResult]/[android.net.Uri]
     * extraction so the CSRF / redirect / error-canonicalization policy is unit-testable.
     *
     * Fail-closed rules (mirrors RFC 6749 Section 10.12): a returned authorization code is accepted only
     * when the redirect URI matched and the returned [returnedState] is present and equal to the
     * [expectedState] we sent; a missing or mismatched state is rejected as a possible CSRF /
     * response-injection attempt.
     */
    internal fun decideAuthResult(
        resultCode: Int,
        hasUriData: Boolean,
        redirectValid: Boolean,
        code: String?,
        returnedState: String?,
        error: String?,
        errorDescription: String?,
        expectedState: String?,
    ): AuthResult {
        if (resultCode == Activity.RESULT_CANCELED) {
            return AuthResult.Cancelled
        }
        if (resultCode != Activity.RESULT_OK || !hasUriData) {
            return AuthResult.Error("platform_error", "Result not OK or no data")
        }
        if (!redirectValid) {
            return AuthResult.Error("invalid_redirect", KrdpassMessages.INVALID_REDIRECT)
        }
        if (code != null) {
            return if (expectedState.isNullOrBlank() || returnedState.isNullOrBlank() || expectedState != returnedState) {
                AuthResult.Error("state_mismatch", KrdpassMessages.STATE_MISMATCH)
            } else {
                AuthResult.Success(code, returnedState)
            }
        }
        if (error != null) {
            // Fail closed: the returned state must be present AND equal to the state we sent.
            if (expectedState.isNullOrBlank() || returnedState.isNullOrBlank() || expectedState != returnedState) {
                return AuthResult.Error("state_mismatch", KrdpassMessages.STATE_MISMATCH)
            }

            val canonicalError = when (error) {
                "access_denied", "user_cancelled", "login_required", "consent_denied" -> "cancelled"
                else -> error
            }
            return AuthResult.Error(canonicalError, errorDescription)
        }
        return AuthResult.Error("no_code", KrdpassMessages.NO_CODE)
    }

    private fun complete(result: AuthResult) {
        // getAndSet detaches the whole flight in one op: the timeout + callback come from it, and a
        // re-entrant authenticate()/signIn() from within the callback installs a fresh holder safely.
        val flight = inFlight.getAndSet(null) ?: return
        flight.timeoutJob?.cancel()
        flight.callback(result)
    }

    /**
     * Cancel any in-flight authentication (authenticate/signIn) flow.
     *
     * Useful when the user returns to your app without completing the flow in
     * KRDPASS (app-switch back). After cancellation, a new flow can start.
     *
     * @param timeout when true, the in-flight flow is finished as a Timeout instead of a
     *   Cancellation. Defaults to false (cancellation).
     */
    @JvmStatic
    @JvmOverloads
    public fun cancelPendingAuthentication(timeout: Boolean = false): Unit =
        finishExternally(if (timeout) AuthResult.Timeout else AuthResult.Cancelled)

    /**
     * Deliver a terminal [result] to an in-flight flow from outside it: the app-switch-back
     * cancel and the forced timeout. Hops to the main thread (where `complete()` mutates the
     * launcher state) when an owner is available; the post-hop same-flight guard ensures a
     * stale external cancel can never settle a NEWER flow claimed after the hop was posted.
     */
    private fun finishExternally(result: AuthResult) {
        val flight = inFlight.get() ?: return
        val owner = activeLifecycleOwner
        if (owner != null) {
            owner.lifecycleScope.launch(Dispatchers.Main) {
                if (inFlight.get() === flight) complete(result)
            }
        } else {
            if (inFlight.get() === flight) complete(result)
        }
    }

    private fun scheduleTimeout(flight: InFlight, owner: LifecycleOwner, timeout: kotlin.time.Duration): Job =
        owner.lifecycleScope.launch(Dispatchers.Main) {
            delay(timeout)
            // Only fire for THIS flight: `===` guards against a later, re-claimed flow.
            if (inFlight.get() === flight) {
                log("WARN", "Auth timed out")
                complete(AuthResult.Timeout)
            }
        }

    @JvmStatic
    public fun generatePkcePair(): PkcePair = PkceGenerator.generate()

    @JvmStatic
    public fun generateState(): String {
        val bytes = ByteArray(STATE_ENTROPY_BYTES)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP).replace("=", "")
    }

    // --- Public Utility Methods (Stateless) ---
    
    @JvmStatic
    public suspend fun getUserInfo(accessToken: String): KrdpassUserInfo = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).getUserInfo(accessToken)
    }

    @JvmStatic
    public suspend fun refreshTokens(refreshToken: String, scope: String? = null): KrdpassTokenResult = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).refreshTokens(refreshToken, scope)
    }

    @JvmStatic
    public suspend fun revokeToken(token: String, tokenTypeHint: String? = null): Unit = withContext(Dispatchers.IO) {
         val c = config ?: throw IllegalStateException("Not initialized")
         CasClient(c.clientId, c.environment).revokeToken(token, tokenTypeHint)
    }

    /**
     * Verify an OIDC/JWT against the configured environment's JWKS and validate standard claims
     * (signature, required `exp`, and `aud` bound to the configured `clientId`). Delegates to
     * [TokenVerifier]. This convenience verifier does NOT pin the issuer; for full issuer-pinned
     * verification use the stateless [TokenVerifier] internals.
     *
     * The first call performs blocking network I/O (JWKS fetch), so call this off the main thread.
     *
     * @throws IllegalStateException if the SDK is not initialized.
     */
    @JvmStatic
    public fun verifyToken(
        idToken: String,
        clockSkewSeconds: Long = 60
    ): Map<String, Any?> {
        val c = config ?: throw IllegalStateException("Not initialized")
        return TokenVerifier.verifyToken(
            c.environment.jwksEndpoint, idToken, issuer = null, audience = c.clientId, clockSkewSeconds)
    }

    /**
     * Decode a JWT's claims **without verifying its signature**.
     *
     * SECURITY: the returned claims are NOT authenticated and MUST NOT drive any trust or
     * authorization decision. Always [verifyToken] first; this is only for cosmetic display of an
     * already-verified token.
     *
     * @throws IllegalArgumentException if [token] is not a parseable JWT.
     */
    @JvmStatic
    public fun decodeTokenUnverified(token: String): Map<String, Any?> =
        TokenVerifier.decodeTokenUnverified(token)
}
