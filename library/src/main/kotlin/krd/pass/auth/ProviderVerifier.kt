package krd.pass.auth

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Provider app-identity trust: verifies the installed KRDPASS app is present and signed with an
 * expected certificate before the SDK will launch it.
 */
internal object ProviderVerifier {

    /**
     * Checks pin configured, package installed, and signing cert SHA-256 matching a known
     * fingerprint. Returns an error description on failure, or null if the launch may proceed.
     * An empty pin set fails closed in Production (launching unpinned would silently reopen the
     * sideload attack) and skips the cert check in Development.
     */
    fun checkInstalled(context: Context, environment: KrdpassEnvironment): String? {
        val expected = environment.providerSigningCertsSha256
        val isProduction = environment == KrdpassEnvironment.Production

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
     * Pure fail-closed pinning decision, separated from PackageManager I/O so the security policy
     * is unit-testable. [installedCerts] is null when the provider is not installed.
     */
    fun evaluateSigningPin(
        installedCerts: Set<String>?,
        expected: Set<String>,
        isProduction: Boolean,
    ): String? {
        if (expected.isEmpty()) {
            // Production must always pin; an empty set is a build misconfiguration, not a valid
            // skip. Development leaves pinning optional for emulators and local debug APKs.
            return if (isProduction) {
                "KRDPASS installation could not be verified (provider signing pin is not configured)."
            } else {
                null
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
            // signingCertificateHistory on purpose: it includes rotated-away certs, so a KRDPASS
            // signing key rotation does not brick installed relying apps. The accepted cost: a
            // superseded key satisfies the pin until this SDK's own pin list drops it.
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
