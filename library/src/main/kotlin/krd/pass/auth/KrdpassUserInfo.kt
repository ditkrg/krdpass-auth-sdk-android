package krd.pass.auth

/**
 * User information claims returned by the UserInfo endpoint: typed access to standard OpenID
 * Connect claims and KRDPASS-specific claims.
 */
public data class KrdpassUserInfo(
    val sub: String,
    val name: String? = null,
    val givenName: String? = null,
    val familyName: String? = null,
    val picture: String? = null,
    val email: String? = null,
    val citizenFirst: String? = null,
    val citizenSecond: String? = null,
    val citizenThird: String? = null,
    val citizenSurname: String? = null,
    val citizenProfilePicture: String? = null,
    val birthdate: String? = null,
    val sexAtBirth: String? = null,
    val upn: String? = null,
    /** Must be stored, and never displayed. */
    val upns: List<String> = emptyList(),
    val did: String? = null,

    /** Raw claims map from the UserInfo endpoint, for custom or non-standard fields. */
    val raw: Map<String, Any?> = emptyMap()
) {
    /**
     * The four citizen name parts joined in registry order with a single space, or null when none
     * carries a usable value. Blank parts are dropped, so an
     * account shows the same name on every platform.
     */
    public val citizenFullName: String?
        get() = listOfNotNull(citizenFirst, citizenSecond, citizenThird, citizenSurname)
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .ifEmpty { null }
            ?.joinToString(" ")

    override fun toString(): String {
        return "KrdpassUserInfo(sub=[REDACTED], name=[REDACTED])"
    }
}
