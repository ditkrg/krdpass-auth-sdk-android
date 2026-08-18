package krd.pass.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCaller
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityOptionsCompat
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
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Receives the outcome of a client-only [KrdpassAuth.signIn]. A two-method interface rather than a
 * `Result`-taking lambda: `kotlin.Result` is an inline value class whose mangled JVM accessor
 * names Java cannot call.
 */
public interface SignInCallback {
    public fun onSuccess(tokens: KrdpassTokenResult)
    public fun onFailure(error: Throwable)
}

/**
 * Main SDK singleton for Sign in with KRDPASS. Call [initialize], then [register] in your
 * Activity's `onCreate`, then start a flow with [signIn] (client-only PKCE) or [authenticate]
 * (backend-mediated, with a request URI from your server's `/oauth/par`).
 */
public object KrdpassAuth {

    private const val NOT_REGISTERED =
        "KrdpassAuth not registered. Call KrdpassAuth.register(this) in onCreate()."

    /** CSRF `state` / OIDC `nonce` entropy: 32 bytes (256 bits) of SecureRandom. */
    private const val STATE_ENTROPY_BYTES = 32

    /**
     * Default caller timeout for [authenticate] and [signIn], in milliseconds. Milliseconds rather
     * than [kotlin.time.Duration] across the public surface: Duration mangles the JVM name into an
     * identifier Java cannot call.
     */
    public const val DEFAULT_TIMEOUT_MILLIS: Long = 5 * 60 * 1000L

    @JvmStatic
    @Volatile
    public var logger: KrdpassLogger? = null

    // Process-scoped, not the owner's lifecycleScope: a configuration change destroys that scope
    // and would drop the re-adopted flight's result. The flight timeout stops the coroutine leaking.
    private val sdkScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    @JvmStatic
    @Volatile
    public var config: KrdpassConfig? = null
        private set

    // @Volatile: written on Main but read on the caller thread by the off-Main authenticate() path.
    @Volatile
    private var activeLauncher: ActivityResultLauncher<Intent>? = null
    @Volatile
    private var activeLifecycleOwner: LifecycleOwner? = null
    @Volatile
    private var appContext: Context? = null

    private val inFlight = AtomicReference<Flight?>(null)

    /**
     * Initialize the SDK. Call in Application.onCreate() or MainActivity.onCreate().
     * @throws KrdpassError.ConfigurationError if [config] is unusable.
     */
    @JvmStatic
    public fun initialize(config: KrdpassConfig) {
        validateConfig(config)
        this.config = config
        TokenVerifier.clearCache()
        log("INFO", "KrdpassAuth initialized")
    }

    /**
     * Register an Activity to handle KRDPASS authentication results.
     * **Must be called in Activity.onCreate()**, before the Activity is STARTED.
     */
    @JvmStatic
    public fun register(activity: ComponentActivity) {
        register(activity as ActivityResultCaller, activity as LifecycleOwner)
    }

    /**
     * Generic register for ActivityResultCaller + LifecycleOwner (Fragments). Config-change flight
     * re-adoption detects recreation via [Activity.isChangingConfigurations], so it only applies to
     * Activity owners: a Fragment host's in-flight flow is still cancelled on rotation.
     */
    @JvmStatic
    public fun register(caller: ActivityResultCaller, lifecycleOwner: LifecycleOwner) {
        // Application Context, so the provider certificate check works even for a Fragment owner.
        appContext = appContext
            ?: (caller as? Context)?.applicationContext
            ?: (lifecycleOwner as? Context)?.applicationContext

        val launcher = caller.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            handleActivityResult(result)
        }

        lifecycleOwner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) {
                activeLauncher = launcher
                activeLifecycleOwner = owner
                // Re-adopt a flight orphaned by a configuration change: the old host's lifecycleScope
                // and timeout job died with it (the dead job is the marker), so re-point and reschedule.
                inFlight.get()?.let { flight ->
                    // A null deadline means the flight has not launched yet (signIn's PAR round
                    // trip): no host, no timeout, nothing to re-adopt.
                    val deadline = flight.deadline ?: return@let
                    if (flight.launchOwner !== owner && flight.timeoutJob?.isActive != true) {
                        // A cancelled job can be momentarily "not active yet not done"; the explicit
                        // cancel guarantees the old one can never fire after the new one is installed.
                        flight.timeoutJob?.cancel()
                        flight.launchOwner = owner
                        val remaining = deadline - kotlin.time.TimeSource.Monotonic.markNow()
                        if (remaining.isPositive()) {
                            flight.timeoutJob = scheduleTimeout(flight, owner, remaining)
                        } else {
                            log("WARN", "Auth timed out")
                            deliver(flight, AuthResult.Timeout)
                        }
                    }
                }
            }

            override fun onDestroy(owner: LifecycleOwner) {
                // A launching host destroyed for real must release the slot, or every future
                // authenticate() returns Busy. A configuration change is not a real destroy: the
                // recreated host re-registers and onResume re-adopts the flight.
                val flight = inFlight.get()
                if (flight != null &&
                    flight.launchOwner === owner &&
                    (owner as? Activity)?.isChangingConfigurations != true
                ) {
                    log("INFO", "Launching activity destroyed mid-flow; cancelling")
                    deliver(flight, AuthResult.Cancelled)
                }
                if (activeLifecycleOwner == owner) {
                    log("INFO", "Activity destroyed, cleaning up auth launcher")
                    activeLauncher = null
                    activeLifecycleOwner = null
                }
            }
        })

        activeLauncher = launcher
        activeLifecycleOwner = lifecycleOwner
        log("DEBUG", "Registered ActivityResultLauncher for lifecycle: $lifecycleOwner")
    }

    /**
     * Launch KRDPASS for authentication (server-mediated mode).
     *
     * @param requestUri The request URI returned from your backend's /oauth/par endpoint.
     * @param state The state your backend's PAR call returned; the SDK fails closed
     *   (invalid_request) when it is null or blank: CSRF validation cannot be skipped.
     * @param timeoutMillis How long to wait for the user to finish in KRDPASS. Must be positive.
     * @param callback Receives the result exactly once.
     */
    @JvmStatic
    @JvmOverloads
    public fun authenticate(
        requestUri: String,
        state: String?,
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
        callback: (AuthResult) -> Unit
    ) {
        startAuthenticationFlight(requestUri, state, timeoutMillis, callback)
    }

    /** [authenticate], returning the claimed flight so a suspending caller can cancel only its own. */
    private fun startAuthenticationFlight(
        requestUri: String,
        state: String?,
        timeoutMillis: Long,
        callback: (AuthResult) -> Unit,
    ): Flight? {
        val owner = activeLifecycleOwner
        if (activeLauncher == null || owner == null) {
            callback(AuthResult.Error("platform_error", NOT_REGISTERED))
            return null
        }
        val currentConfig = config ?: run {
            callback(AuthResult.Error("platform_error",
                "KrdpassAuth not initialized. Call KrdpassAuth.initialize(config)."))
            return null
        }
        if (timeoutMillis <= 0) {
            callback(AuthResult.Error("platform_error", "timeoutMillis must be positive"))
            return null
        }
        val flight = claimFlight() ?: run {
            callback(AuthResult.Busy)
            return null
        }
        // Settled before the callback was installed (a cancel racing the claim): deliver it here.
        flight.awaitOn(callback)?.let {
            callback(it)
            return null
        }
        log("INFO", "Starting authentication")
        val context = appContext ?: (owner as? Context)
        beginLaunch(
            flight,
            startAuthentication(context, currentConfig, requestUri, state ?: ""),
            expectedState = state ?: "",
            timeout = timeoutMillis.milliseconds,
        )
        return flight
    }

    private fun claimFlight(): Flight? {
        val flight = Flight()
        if (inFlight.compareAndSet(null, flight)) return flight
        log("WARN", "Authentication already in progress")
        return null
    }

    private fun beginLaunch(
        flight: Flight,
        launch: AuthLaunch,
        expectedState: String,
        timeout: kotlin.time.Duration,
    ) {
        when (launch) {
            is AuthLaunch.Failure -> deliver(flight, launch.error)
            is AuthLaunch.Ready -> {
                val launcher = activeLauncher
                val owner = activeLifecycleOwner
                if (launcher == null || owner == null) {
                    deliver(flight, AuthResult.Error("platform_error", NOT_REGISTERED))
                    return
                }
                flight.expectedState = expectedState
                flight.launchOwner = owner
                // Scheduled before launching: launcher.launch() is a slow app-switch, and the
                // deadline covers it. delay() means the job can't fire during the launch itself.
                flight.deadline = kotlin.time.TimeSource.Monotonic.markNow() + timeout
                flight.timeoutJob = scheduleTimeout(flight, owner, timeout)
                // Never open KRDPASS for a flow a cancel already settled.
                if (flight.result != null) {
                    flight.timeoutJob?.cancel()
                    return
                }
                try {
                    launcher.launch(launch.intent, launch.activityOptionsCompat)
                    log("INFO", "Authentication flow started")
                } catch (e: Exception) {
                    log("ERROR", "Failed to launch: ${e.message}")
                    deliver(flight, AuthResult.Error("launch_failed", e.message))
                }
            }
        }
    }

    private suspend fun awaitLaunch(
        flight: Flight,
        launch: AuthLaunch,
        expectedState: String,
        timeout: kotlin.time.Duration,
    ): AuthResult = suspendCancellableCoroutine { cont ->
        // A cancel that arrived during the PAR round trip already settled the flight: hand its
        // result back instead of launching an abandoned flow.
        val settled = flight.awaitOn { if (cont.isActive) cont.resume(it) }
        if (settled != null) cont.resume(settled)
        else beginLaunch(flight, launch, expectedState, timeout)
    }

    /** Bound a caller-requested [timeout] by the PAR request_uri's lifetime: the consent session dies with it. */
    internal fun boundToParExpiry(timeout: kotlin.time.Duration, parExpiresInSeconds: Int): kotlin.time.Duration =
        minOf(timeout, parExpiresInSeconds.seconds)

    private fun authResultToError(result: AuthResult): KrdpassError = when (result) {
        is AuthResult.Cancelled -> KrdpassError.UserCancelled()
        is AuthResult.Timeout -> KrdpassError.Timeout()
        is AuthResult.Busy -> KrdpassError.Busy()
        is AuthResult.Error -> KrdpassError.AuthenticationFailed(
            result.message ?: result.error, code = result.error, installUrl = result.installUrl)
        is AuthResult.Success -> error("authResultToError must not be called with Success")
    }

    /**
     * Suspending [authenticate]. Cancelling the calling coroutine releases the in-flight slot, so
     * the next flow is not turned away as [AuthResult.Busy].
     */
    @JvmSynthetic
    public suspend fun authenticate(
        requestUri: String,
        state: String?,
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS
    ): AuthResult = suspendCancellableCoroutine { cont ->
        val flight = startAuthenticationFlight(requestUri, state, timeoutMillis) { result ->
            if (cont.isActive) cont.resume(result)
        }
        cont.invokeOnCancellation { flight?.let { deliverOnMain(it, AuthResult.Cancelled) } }
    }

    /**
     * Client-only sign-in: the SDK runs PKCE and PAR itself, launches KRDPASS, exchanges the
     * authorization code, and validates the returned id_token against the nonce it pushed.
     * Use [authenticate] instead when your backend owns the PAR call.
     *
     * @param scopes OAuth scopes to request. Must not be empty.
     * @param timeoutMillis Must be positive; additionally bounded by the PAR `request_uri` lifetime.
     * @param callback Receives either the tokens or a [KrdpassError], exactly once.
     */
    @JvmStatic
    @JvmOverloads
    public fun signIn(
        scopes: List<String> = listOf(KrdpassScopes.OPENID, KrdpassScopes.PROFILE),
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
        callback: SignInCallback
    ) {
        startSignInFlight(scopes, timeoutMillis, callback)
    }

    /** [signIn], returning the claimed flight so a suspending caller can cancel only its own. */
    private fun startSignInFlight(
        scopes: List<String>,
        timeoutMillis: Long,
        callback: SignInCallback,
    ): Flight? {
        if (scopes.isEmpty()) {
            callback.onFailure(KrdpassError.ConfigurationError("scopes cannot be empty"))
            return null
        }
        if (timeoutMillis <= 0) {
            callback.onFailure(KrdpassError.ConfigurationError("timeoutMillis must be positive"))
            return null
        }
        if (activeLifecycleOwner == null) {
            callback.onFailure(KrdpassError.ConfigurationError("Auth not registered with an Activity"))
            return null
        }
        val currentConfig = config ?: run {
            callback.onFailure(KrdpassError.ConfigurationError("Not initialized"))
            return null
        }

        // Claimed before PAR starts: the round trip runs inside the claim, so a concurrent flow is
        // told Busy rather than launching over this one, and a cancel has something to settle.
        val flight = claimFlight() ?: run {
            callback.onFailure(KrdpassError.Busy())
            return null
        }

        // sdkScope, not owner.lifecycleScope: the pipeline must outlive a configuration change.
        sdkScope.launch { runSignIn(currentConfig, scopes, timeoutMillis.milliseconds, flight, callback) }
        return flight
    }

    /**
     * The client-only pipeline. Both CAS legs run inside [translatingCasErrors], so a permanent
     * OAuth failure reaches the caller as [KrdpassError.AuthenticationFailed] rather than as a
     * retryable network error.
     */
    private suspend fun runSignIn(
        currentConfig: KrdpassConfig,
        scopes: List<String>,
        timeout: kotlin.time.Duration,
        flight: Flight,
        callback: SignInCallback,
    ) {
        var settled = false
        try {
            val context = appContext ?: (activeLifecycleOwner as? Context)
            val (launch, pending) = startSignIn(context, currentConfig, scopes)
            val boundedTimeout = boundToParExpiry(timeout, pending.parExpiresInSeconds)
            when (val result = awaitLaunch(flight, launch, pending.state, boundedTimeout)) {
                is AuthResult.Success -> {
                    val tokens = translatingCasErrors {
                        exchangeAndValidate(result.code, pending.codeVerifier, pending.nonce, currentConfig)
                    }
                    // Outside the try: a host whose onSuccess throws must not then be handed
                    // onFailure for the same flow.
                    settled = true
                    callback.onSuccess(tokens)
                }
                else -> callback.onFailure(authResultToError(result))
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Structured-concurrency cancellation must propagate, not become a KrdpassError.
            throw e
        } catch (e: Exception) {
            if (settled) throw e
            // Anything unexpected is a failure of this sign-in, not a retryable transport problem.
            callback.onFailure(
                if (e is KrdpassError) e
                else KrdpassError.AuthenticationFailed("Unexpected sign-in failure: ${e.message}"))
        } finally {
            releaseFlight(flight)
        }
    }

    /**
     * Suspending [signIn]. Throws the same [KrdpassError] subtypes the callback form delivers.
     * Cancelling the calling coroutine abandons the flow and releases the in-flight slot.
     */
    @JvmSynthetic
    public suspend fun signIn(
        scopes: List<String> = listOf(KrdpassScopes.OPENID, KrdpassScopes.PROFILE),
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS
    ): KrdpassTokenResult = suspendCancellableCoroutine { cont ->
        val flight = startSignInFlight(scopes, timeoutMillis, object : SignInCallback {
            override fun onSuccess(tokens: KrdpassTokenResult) {
                if (cont.isActive) cont.resume(tokens)
            }

            override fun onFailure(error: Throwable) {
                if (cont.isActive) cont.resumeWithException(error)
            }
        })
        cont.invokeOnCancellation { flight?.let { deliverOnMain(it, AuthResult.Cancelled) } }
    }

    // Stateless, launch-decoupled API: holds no per-flow state, launcher or LifecycleOwner, so any
    // host (Expo/RN, a Service, Compose) reuses the full security flow.

    public sealed class AuthLaunch {
        /**
         * Prepared provider launch. Every host must pass [activityOptions] with [intent]:
         * `Activity.startActivityForResult(intent, requestCode, activityOptions)`.
         * The host must then call [handleAuthorizationResult] with the matching result.
         */
        public data class Ready(public val intent: Intent) : AuthLaunch() {
            // A body property, not a constructor parameter: Kotlin derives the constructor and copy()
            // from the parameter list, so moving it there would change the published ABI.
            internal val activityOptionsCompat: ActivityOptionsCompat = authenticationLaunchOptions()

            /**
             * Launch options carrying Android's identity-sharing request, so the provider can
             * attribute the Activity result to its caller. Never launch [intent] without them.
             * A plain [Bundle] so androidx.core stays off this SDK's public contract.
             */
            public val activityOptions: Bundle = activityOptionsCompat.toBundle() ?: Bundle()
        }
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
        private val consumed = java.util.concurrent.atomic.AtomicBoolean(false)

        /**
         * Claim this pending for its one and only [finishSignIn]: the authorization code is spent
         * and the code verifier and nonce must never be reused.
         */
        internal fun claim(): Boolean = consumed.compareAndSet(false, true)

        override fun toString(): String = "SignInPending(REDACTED)"
    }

    /**
     * Prepare a backend-driven (server mode) authorization launch: arg validation, provider
     * cert-pin check, and the `setPackage()`-locked Intent. Does not launch and holds no state.
     * The caller launches [AuthLaunch.Ready.intent] with [AuthLaunch.Ready.activityOptions] and
     * passes [state] back to [handleAuthorizationResult]. With a null [context] the cert-pin
     * policy fails closed when a pin is configured.
     */
    @JvmStatic
    public fun startAuthentication(
        context: Context?,
        config: KrdpassConfig,
        requestUri: String,
        state: String,
    ): AuthLaunch {
        // Up front, so an unusable redirectUri is reported as such instead of surfacing later as a
        // misleading invalid_redirect on the way back from the provider.
        try {
            validateConfig(config)
        } catch (e: KrdpassError.ConfigurationError) {
            return AuthLaunch.Failure(AuthResult.Error("invalid_request", e.message))
        }
        return prepareLaunch(context, config, requestUri, state)
    }

    private fun prepareLaunch(
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
     * Result policy for a launch started by [startAuthentication]/[startSignIn]: the fail-closed
     * CSRF/redirect/error canonicalization. [expectedState] is the state the host launched with.
     */
    @JvmStatic
    public fun handleAuthorizationResult(
        resultCode: Int,
        data: Intent?,
        config: KrdpassConfig,
        expectedState: String,
    ): AuthResult {
        // getQueryParameter throws on an opaque URI, and arguments evaluate eagerly, so reading
        // one here would escape this policy and leave the flight unsettled. An opaque result can
        // never be our https redirect anyway, so it fails closed as invalid_redirect.
        val uri = data?.data?.takeIf { it.isHierarchical }
        return decideAuthResult(
            resultCode = resultCode,
            hasUriData = data?.data != null,
            redirectValid = uri != null && config.isValidRedirectUri(uri),
            code = uri?.getQueryParameter("code"),
            returnedState = uri?.getQueryParameter("state"),
            error = uri?.getQueryParameter("error"),
            errorDescription = uri?.getQueryParameter("error_description"),
            expectedState = expectedState,
            // getQueryParameter percent-decodes, so `iss` arrives as the plain issuer string.
            returnedIss = uri?.getQueryParameter("iss"),
            expectedIssuer = config.environment.authServerUrl,
        )
    }

    /**
     * Prepare a client-mode (PKCE) sign-in: PKCE + PAR + the launch Intent. Returns the launch and
     * an opaque [SignInPending] the host passes back to [finishSignIn].
     *
     * @throws KrdpassError.ConfigurationError if [scopes] is empty or [config] is unusable.
     * @throws KrdpassError.NetworkError or [KrdpassError.AuthenticationFailed] if PAR fails.
     */
    @JvmStatic
    public suspend fun startSignIn(
        context: Context?,
        config: KrdpassConfig,
        scopes: List<String> = listOf(KrdpassScopes.OPENID, KrdpassScopes.PROFILE),
    ): Pair<AuthLaunch, SignInPending> {
        if (scopes.isEmpty()) throw KrdpassError.ConfigurationError("scopes cannot be empty")
        validateConfig(config)
        return translatingCasErrors {
            withContext(Dispatchers.IO) {
                val pkce = generatePkcePair()
                val state = generateState()
                val nonce = generateState()
                val par = CasClient.forConfig(config.clientId, config.environment)
                    .pushAuthorizationRequest(pkce.codeChallenge, config.redirectUri, scopes, state, nonce)
                val launch = prepareLaunch(context, config, par.requestUri, state)
                launch to SignInPending(pkce.codeVerifier, state, nonce, par.expiresIn)
            }
        }
    }

    /**
     * Finish a client-mode sign-in: apply the result policy, exchange the code, and validate the
     * id_token (nonce binding). Throws [KrdpassError]. [pending] is single-use; a second call
     * fails rather than replaying its code verifier and nonce.
     */
    @JvmStatic
    public suspend fun finishSignIn(
        resultCode: Int,
        data: Intent?,
        config: KrdpassConfig,
        pending: SignInPending,
    ): KrdpassTokenResult = withContext(Dispatchers.IO) {
        if (!pending.claim()) {
            throw KrdpassError.ConfigurationError(
                "This SignInPending was already used. Start a new sign-in with startSignIn().")
        }
        when (val result = handleAuthorizationResult(resultCode, data, config, pending.state)) {
            is AuthResult.Success -> translatingCasErrors {
                exchangeAndValidate(result.code, pending.codeVerifier, pending.nonce, config)
            }
            else -> throw authResultToError(result)
        }
    }

    private suspend fun exchangeAndValidate(
        code: String,
        codeVerifier: String,
        nonce: String,
        config: KrdpassConfig,
    ): KrdpassTokenResult = withContext(Dispatchers.IO) {
        val tokens = CasClient.forConfig(config.clientId, config.environment)
            .exchangeCodeForTokens(code, codeVerifier, config.redirectUri)
        TokenVerifier.validateIdToken(config.environment, config.clientId, tokens.idToken, nonce)
        tokens
    }

    private fun validateConfig(config: KrdpassConfig) {
        val uri = config.redirectUri.toUri()
        val problem = when {
            config.clientId.isBlank() -> "clientId cannot be blank"
            config.redirectUri.isBlank() -> "redirectUri cannot be blank"
            !uri.scheme.equals("https", ignoreCase = true) -> "redirectUri must use HTTPS"
            uri.host.isNullOrBlank() -> "redirectUri must have a valid host"
            !config.isValidRedirectUri(uri) ->
                "redirectUri must not contain user info, a fragment, malformed encoding, " +
                    "or OAuth response parameters"
            else -> return
        }
        throw KrdpassError.ConfigurationError(problem)
    }

    /** The provider receives Android's shared caller identity, not a caller-supplied Intent extra. */
    private fun authenticationLaunchOptions(): ActivityOptionsCompat =
        ActivityOptionsCompat.makeBasic().setShareIdentityEnabled(true)

    /**
     * `redirect_uri` is redundant under RFC 9126, which binds it in the PAR body, but the provider
     * reads it from here to carry an OAuth error back before it resolves the request_uri; dropping
     * it costs `request_expired` on every already-installed KRDPASS build. `state` rides along
     * because the provider echoes it on redirects it generates before resolving the request_uri.
     */
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
        val currentConfig = config ?: run {
            log("ERROR", "Activity result arrived but KrdpassAuth is not initialized; dropping it. " +
                "Call KrdpassAuth.initialize(config) before starting a flow.")
            return
        }
        deliver(
            flight,
            handleAuthorizationResult(result.resultCode, result.data, currentConfig, flight.expectedState),
        )
    }

    /**
     * Pure fail-closed auth-result policy, separated from the Android extraction so it is
     * unit-testable. RFC 6749 10.12: a code is accepted only when the redirect matched and
     * [returnedState] is present and equals [expectedState]. RFC 9207: a code with a [returnedIss]
     * that is not [expectedIssuer] is rejected (mix-up attack); an absent `iss` is accepted (it is
     * optional, and CAS omits it on errors). Present-but-blank is already invalid_redirect.
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
        returnedIss: String?,
        expectedIssuer: String?,
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
            return when {
                isStateMismatch(expectedState, returnedState) ->
                    AuthResult.Error("state_mismatch", KrdpassMessages.STATE_MISMATCH)
                returnedIss != null && returnedIss != expectedIssuer ->
                    AuthResult.Error("issuer_mismatch", KrdpassMessages.ISSUER_MISMATCH)
                else -> AuthResult.Success(code, returnedState)
            }
        }
        if (error != null) {
            if (isStateMismatch(expectedState, returnedState)) {
                return AuthResult.Error("state_mismatch", KrdpassMessages.STATE_MISMATCH)
            }

            val canonicalError = when (error) {
                "access_denied", "user_cancelled", "login_required", "consent_denied" -> "cancelled"
                else -> error
            }
            // The provider's error_description is arbitrary upstream text; cap what reaches the app.
            return AuthResult.Error(canonicalError, errorDescription?.bounded())
        }
        return AuthResult.Error("no_code", KrdpassMessages.NO_CODE)
    }

    private fun isStateMismatch(expectedState: String?, returnedState: String?): Boolean {
        if (expectedState.isNullOrBlank() || returnedState.isNullOrBlank()) return true
        return !MessageDigest.isEqual(
            expectedState.toByteArray(Charsets.UTF_8),
            returnedState.toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * The one terminal path: [Flight.settle] picks the single winner, so a late timeout, a
     * duplicate cancel and the activity result racing each other still deliver exactly once.
     */
    private fun deliver(flight: Flight, result: AuthResult) {
        if (!flight.settle(result)) return
        releaseFlight(flight)
        // The one place every terminal outcome logs; the result arrives via the activity-result
        // API, so there is no HTTP call for a backend or proxy to show instead.
        log("INFO", "Authentication finished: ${result.logLabel}")
        // No waiter means signIn is still inside its PAR round trip: it reads the settled outcome
        // itself rather than launching.
        flight.takeWaiter()?.invoke(result)
    }

    /** Free the slot [flight] holds and stop its timeout. Idempotent, and never touches a newer flight. */
    private fun releaseFlight(flight: Flight) {
        inFlight.compareAndSet(flight, null)
        flight.timeoutJob?.cancel()
    }

    /**
     * Cancel any in-flight authentication (authenticate/signIn) flow, e.g. when the user
     * app-switches back without finishing in KRDPASS. After cancellation, a new flow can start.
     *
     * @param timeout when true, the flow finishes as a Timeout instead of a Cancellation.
     */
    @JvmStatic
    @JvmOverloads
    public fun cancelPendingAuthentication(timeout: Boolean = false) {
        val flight = inFlight.get() ?: return
        deliverOnMain(flight, if (timeout) AuthResult.Timeout else AuthResult.Cancelled)
    }

    /**
     * Deliver a terminal [result] from outside the flight (cancel, forced timeout), hopping to the
     * main thread when possible. [deliver]'s settle makes the hop safe: a stale cancel can never
     * settle a flight claimed after it was posted.
     */
    private fun deliverOnMain(flight: Flight, result: AuthResult) {
        val owner = activeLifecycleOwner
        if (owner != null) owner.lifecycleScope.launch(Dispatchers.Main) { deliver(flight, result) }
        else deliver(flight, result)
    }

    private fun scheduleTimeout(flight: Flight, owner: LifecycleOwner, timeout: kotlin.time.Duration): Job =
        owner.lifecycleScope.launch(Dispatchers.Main) {
            delay(timeout)
            if (flight.result == null) {
                log("WARN", "Auth timed out")
                deliver(flight, AuthResult.Timeout)
            }
        }

    @JvmStatic
    public fun generatePkcePair(): PkcePair = PkceGenerator.generate()

    @JvmStatic
    public fun generateState(): String = PkceGenerator.randomUrlSafeToken(STATE_ENTROPY_BYTES)

    // Token operations come in two forms: one reading the config installed by initialize(), one
    // taking clientId + environment explicitly (the RN bridge, which never initializes). The
    // explicit form is what keeps CasClient off the public ABI.

    private fun requireConfig(): KrdpassConfig =
        config ?: throw KrdpassError.ConfigurationError(
            "KrdpassAuth not initialized. Call KrdpassAuth.initialize(config).")

    @JvmStatic
    public suspend fun getUserInfo(accessToken: String): KrdpassUserInfo =
        requireConfig().let { getUserInfo(it.clientId, it.environment, accessToken) }

    /** [getUserInfo] against an explicit client and environment, without initializing the SDK. */
    @JvmStatic
    public suspend fun getUserInfo(
        clientId: String,
        environment: KrdpassEnvironment,
        accessToken: String,
    ): KrdpassUserInfo = withContext(Dispatchers.IO) {
        translatingCasErrors { CasClient.forConfig(clientId, environment).getUserInfo(accessToken) }
    }

    @JvmStatic
    @JvmOverloads
    public suspend fun refreshTokens(refreshToken: String, scope: String? = null): KrdpassTokenResult =
        requireConfig().let { refreshTokens(it.clientId, it.environment, refreshToken, scope) }

    /**
     * [refreshTokens] against an explicit client and environment, without initializing the SDK.
     * A returned non-blank `id_token` is verified the way [verifyToken] verifies one; a refresh
     * response with no `id_token` stays valid, OAuth does not require one.
     */
    @JvmStatic
    @JvmOverloads
    public suspend fun refreshTokens(
        clientId: String,
        environment: KrdpassEnvironment,
        refreshToken: String,
        scope: String? = null,
    ): KrdpassTokenResult = withContext(Dispatchers.IO) {
        val result = translatingCasErrors {
            CasClient.forConfig(clientId, environment).refreshTokens(refreshToken, scope)
        }
        verifyRefreshedIdTokenIfPresent(
            idToken = result.idToken,
            jwksUrl = environment.jwksEndpoint,
            issuer = environment.authServerUrl,
            audience = clientId,
        )
        result
    }

    internal suspend fun verifyRefreshedIdTokenIfPresent(
        idToken: String?,
        jwksUrl: String,
        issuer: String,
        audience: String,
    ) {
        if (idToken.isNullOrBlank()) return
        translatingVerifyErrors {
            TokenVerifier.verifyToken(jwksUrl, idToken, issuer, audience, clockSkewSeconds = 60)
        }
    }

    @JvmStatic
    @JvmOverloads
    public suspend fun revokeToken(token: String, tokenTypeHint: String? = null): Unit =
        requireConfig().let { revokeToken(it.clientId, it.environment, token, tokenTypeHint) }

    /** [revokeToken] against an explicit client and environment, without initializing the SDK. */
    @JvmStatic
    @JvmOverloads
    public suspend fun revokeToken(
        clientId: String,
        environment: KrdpassEnvironment,
        token: String,
        tokenTypeHint: String? = null,
    ): Unit = withContext(Dispatchers.IO) {
        translatingCasErrors { CasClient.forConfig(clientId, environment).revokeToken(token, tokenTypeHint) }
    }

    /**
     * Verify an OIDC/JWT against the configured environment's JWKS: signature, required `exp`,
     * `iss` pinned to the authorization server, `aud` bound to the configured `clientId`.
     * Failures arrive as [KrdpassError.AuthenticationFailed] with these codes:
     * `invalid_id_token`, `network_error` (JWKS fetch failed, retry may help), or
     * `verification_failed`. The nonce replay binding belongs to the [signIn] trust path.
     *
     * @param clockSkewSeconds tolerance for `exp`, `nbf` and `iat`; clamped to 0..300, since a
     *   larger value would effectively switch off the expiry check.
     */
    @JvmStatic
    @JvmOverloads
    public suspend fun verifyToken(
        idToken: String,
        clockSkewSeconds: Long = 60
    ): Map<String, Any?> = requireConfig().let {
        verifyToken(it.clientId, it.environment, idToken, clockSkewSeconds)
    }

    /** [verifyToken] against an explicit client and environment, without initializing the SDK. */
    @JvmStatic
    @JvmOverloads
    public suspend fun verifyToken(
        clientId: String,
        environment: KrdpassEnvironment,
        idToken: String,
        clockSkewSeconds: Long = 60,
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        translatingVerifyErrors {
            // The issuer is pinned, not optional: an unpinned verifier accepts a correctly signed
            // token from any issuer whose keys happen to be in the fetched JWKS.
            TokenVerifier.verifyToken(
                environment.jwksEndpoint,
                idToken,
                issuer = environment.authServerUrl,
                audience = clientId,
                clockSkewSeconds,
            )
        }
    }

    /**
     * Decode a JWT's claims **without verifying its signature**. SECURITY: the returned claims are
     * NOT authenticated and MUST NOT drive any trust decision; always [verifyToken] first.
     *
     * @throws IllegalArgumentException if [token] is not a parseable JWT.
     */
    @JvmStatic
    public fun decodeTokenUnverified(token: String): Map<String, Any?> =
        TokenVerifier.decodeTokenUnverified(token)
}
