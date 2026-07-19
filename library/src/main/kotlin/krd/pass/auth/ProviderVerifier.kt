package krd.pass.auth

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Provider app-identity trust: the "S1" check. Verifies the installed KRDPASS app is present and
 * signed with an expected certificate before the SDK will launch it. Pure security policy +
 * PackageManager I/O, separated from [KrdpassAuth] so it has one home and the fail-closed decision
 * is unit-testable in isolation (see ProviderPinningTest). Mirrors [TokenVerifier] (JWT trust).
 */
internal object ProviderVerifier {

    /**
     * Verifies the KRDPASS provider app is installed with the expected signing certificate.
     * Returns an error description string on failure, or null if all checks pass.
     *
     * Checks, in order:
     *  1. Pin is configured. An empty [KrdpassEnvironment.providerSigningCertsSha256] means "no pin":
     *     in Production this fails closed (never launch unpinned, that would silently reopen the
     *     sideload attack); in Development it skips the cert check for local/debug builds.
     *  2. Package is installed (NameNotFoundException -> provider_not_installed).
     *  3. Signing cert SHA-256 matches a known fingerprint (cert mismatch -> provider_not_installed).
     */
    fun checkInstalled(context: Context, environment: KrdpassEnvironment): String? {
        val expected = environment.providerSigningCertsSha256
        val isProduction = environment == KrdpassEnvironment.Production

        // Fast path: no pin configured, don't even query PackageManager.
        if (expected.isEmpty()) {
            if (!isProduction) {
                log("WARN", "Provider cert pinning is disabled for $environment (empty pin set).")
            }
            return evaluateSigningPin(null, expected, isProduction)
        }

        val installedCerts: Set<String>? = try {
            collectSigningCertSha256(context.packageManager, environment.providerPackage)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
        return evaluateSigningPin(installedCerts, expected, isProduction)
    }

    /**
     * Pure fail-closed pinning decision, separated from PackageManager I/O so the security policy is
     * unit-testable. Returns an error description, or null if the launch may proceed.
     *
     * @param installedCerts SHA-256 fingerprints of the installed provider's signing certs, or null
     *   if the provider is not installed. Ignored when [expected] is empty.
     */
    fun evaluateSigningPin(
        installedCerts: Set<String>?,
        expected: Set<String>,
        isProduction: Boolean,
    ): String? {
        if (expected.isEmpty()) {
            // Production must always pin; an empty set is a build misconfiguration, not a valid skip.
            return if (isProduction) {
                "KRDPASS installation could not be verified (provider signing pin is not configured)."
            } else {
                null // Development: pinning optional for emulators / locally-built debug APKs.
            }
        }
        if (installedCerts == null) {
            return KrdpassMessages.PROVIDER_NOT_INSTALLED
        }
        if (installedCerts.intersect(expected).isEmpty()) {
            return "KRDPASS installation could not be verified. Please reinstall KRDPASS."
        }
        return null
    }

    /** Collects the SHA-256 fingerprints of [pkg]'s signing certs. Throws NameNotFound if absent. */
    private fun collectSigningCertSha256(pm: PackageManager, pkg: String): Set<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo ?: throw PackageManager.NameNotFoundException(pkg)
            val sigs = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners.toList()
                        else signingInfo.signingCertificateHistory.toList()
            sigs.mapTo(mutableSetOf()) { certSha256Hex(it.toByteArray()) }
        } else {
            @Suppress("DEPRECATION")
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            (info.signatures ?: emptyArray()).mapTo(mutableSetOf()) { certSha256Hex(it.toByteArray()) }
        }
    }

    fun certSha256Hex(der: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(der).joinToString(":") { b -> "%02X".format(b) }
    }
}
