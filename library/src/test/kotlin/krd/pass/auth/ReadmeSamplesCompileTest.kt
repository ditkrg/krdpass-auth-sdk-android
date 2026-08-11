package krd.pass.auth

import android.app.Activity
import android.content.Intent
import android.util.Log
import org.junit.Test

/**
 * Compile-only guard for the Kotlin samples in README.md: the build is the assertion. Keep each
 * block a verbatim copy of the README. The Java samples are guarded by JavaInteropTest.
 */
@Suppress("UNUSED_PARAMETER", "UnusedPrivateMember")
class ReadmeSamplesCompileTest {

    private fun quickstartInitialize() {
        KrdpassAuth.initialize(
            KrdpassConfig(
                clientId = "your-client-id",
                redirectUri = "https://auth.your-app.example.com/callback",
                environment = KrdpassEnvironment.Production,
            )
        )
    }

    private fun quickstartRegister(activity: androidx.activity.ComponentActivity) {
        KrdpassAuth.register(activity)
    }

    private suspend fun quickstartClientOnlySuspend(): KrdpassTokenResult =
        KrdpassAuth.signIn(scopes = listOf("openid", "profile"))

    private fun quickstartClientOnlyCallback() {
        KrdpassAuth.signIn(
            scopes = listOf("openid", "profile"),
            callback = object : SignInCallback {
                override fun onSuccess(tokens: KrdpassTokenResult) { /* tokens.accessToken */ }
                override fun onFailure(error: Throwable) { /* see Error handling */ }
            },
        )
    }

    private fun interface ServerMediatedBackend {
        fun getRequestUri(codeChallenge: String, state: String): String
    }

    private fun quickstartServerMediated(yourBackend: ServerMediatedBackend) {
        val pkce = KrdpassAuth.generatePkcePair()
        val state = KrdpassAuth.generateState()

        // Your backend runs the PAR with pkce.codeChallenge and state, and returns the request_uri.
        val requestUri = yourBackend.getRequestUri(pkce.codeChallenge, state)

        KrdpassAuth.authenticate(requestUri = requestUri, state = state) { result ->
            when (result) {
                is AuthResult.Success -> {
                    // send result.code + pkce.codeVerifier + result.state to your backend
                }
                is AuthResult.Cancelled -> { /* usually no UI needed */ }
                is AuthResult.Timeout -> { /* offer retry */ }
                is AuthResult.Busy -> { /* ignore or queue */ }
                is AuthResult.Error ->
                    // A deny reported by KRDPASS on the redirect is NOT Cancelled: it arrives here,
                    // as Error with code "cancelled". result.isCancelled covers both shapes.
                    if (result.isCancelled) { /* usually no UI needed */ }
                    else { /* result.code, result.installUrl */ }
            }
        }
    }

    private fun recoveringAnAbandonedFlow() {
        KrdpassAuth.cancelPendingAuthentication(timeout = false)
    }

    private fun quickstartLogging() {
        KrdpassAuth.logger = KrdpassLogger { level, message -> Log.d("KRDPASS", "[$level] $message") }
    }

    private fun ownHostLaunch(activity: Activity, config: KrdpassConfig, requestUri: String) {
        val state = KrdpassAuth.generateState()
        val requestKrdpass = 1
        val handleError: (AuthResult.Error) -> Unit = {}
        when (val launch = KrdpassAuth.startAuthentication(activity, config, requestUri, state)) {
            is KrdpassAuth.AuthLaunch.Ready ->
                activity.startActivityForResult(launch.intent, requestKrdpass, launch.activityOptions)
            is KrdpassAuth.AuthLaunch.Failure -> handleError(launch.error)
        }
    }

    private suspend fun ownHostClientOnly(
        activity: Activity,
        config: KrdpassConfig,
        resultCode: Int,
        data: Intent?,
    ): KrdpassTokenResult {
        val requestKrdpass = 1
        val (launch, pending) = KrdpassAuth.startSignIn(activity, config)
        if (launch is KrdpassAuth.AuthLaunch.Ready) {
            activity.startActivityForResult(launch.intent, requestKrdpass, launch.activityOptions)
        }

        // Later, in your Activity-result handler:
        val tokens = KrdpassAuth.finishSignIn(resultCode, data, config, pending)
        return tokens
    }

    private fun tokensScopesAndUserInfo(
        tokens: KrdpassTokenResult,
        userInfo: KrdpassUserInfo,
    ): Pair<List<String>, String?> {
        val scopes = listOf(KrdpassScopes.OPENID, KrdpassScopes.PROFILE, KrdpassScopes.CITIZEN_IDENTITY)

        if (tokens.isExpired()) { /* refresh before calling your API */ }

        val displayName = userInfo.citizenFullName ?: userInfo.name
        return scopes to displayName
    }

    private suspend fun statelessTokenOps(
        clientId: String,
        accessToken: String,
    ): KrdpassUserInfo =
        KrdpassAuth.getUserInfo(clientId, KrdpassEnvironment.Production, accessToken)

    @Test
    fun `readme samples compile`() {
    }
}
