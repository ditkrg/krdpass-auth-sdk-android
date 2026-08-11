package krd.pass.auth

/**
 * User information claims returned by the UserInfo endpoint: typed access to standard OpenID
 * Connect claims and KRDPASS-specific claims.
 */
public data class KrdpassUserInfo(
    /** Subject - Identifier for the End-User. */
    val sub: String,

    /** End-User's full name in displayable form including all name parts. */
    val name: String? = null,

    /** Given name(s) or first name(s) of the End-User. */
    val givenName: String? = null,

    /** Surname(s) or last name(s) of the End-User. */
    val familyName: String? = null,

    /** URL of the End-User's profile picture. */
    val picture: String? = null,

    /** End-User's preferred e-mail address (if granted by scope). */
    val email: String? = null,

    /** KRDPASS Specific: Citizen's first name */
    val citizenFirst: String? = null,

    /** KRDPASS Specific: Citizen's second name */
    val citizenSecond: String? = null,

    /** KRDPASS Specific: Citizen's third name */
    val citizenThird: String? = null,

    /** KRDPASS Specific: Citizen's surname */
    val citizenSurname: String? = null,

    /** KRDPASS Specific: Profile picture URL specific to citizen registry */
    val citizenProfilePicture: String? = null,

    /** KRDPASS Specific: Birthdate (ISO8601 format) */
    val birthdate: String? = null,

    /** KRDPASS Specific: Sex at birth (e.g. 'male', 'female') */
    val sexAtBirth: String? = null,

    /** KRDPASS Specific: Unique Personal Number */
    val upn: String? = null,

    /** KRDPASS Specific: historical Unique Personal Numbers. Must be stored, and never displayed. */
    val upns: List<String> = emptyList(),

    /** KRDPASS Specific: Decentralized Identifier */
    val did: String? = null,

    /** Raw claims map from the UserInfo endpoint, for custom or non-standard fields. */
    val raw: Map<String, Any?> = emptyMap()
) {
    /**
     * The four citizen name parts joined in registry order with a single space, or null when none
     * carries a usable value. Blank parts are dropped, matching the iOS/Flutter/RN SDKs, so an
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
