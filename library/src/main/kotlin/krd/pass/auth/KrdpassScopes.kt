package krd.pass.auth

/**
 * Standard OAuth2 scopes supported by KRDPASS.
 */
public object KrdpassScopes {
    /**
     * Required for OpenID Connect flows. Returns the 'sub' claim.
     */
    public const val OPENID: String = "openid"

    /**
     * Returns standard profile claims (name, family_name, given_name, picture).
     */
    public const val PROFILE: String = "profile"

    /**
     * Returns digital identity claims (e.g. citizen_first, citizen_surname, birthdate).
     */
    public const val CITIZEN_IDENTITY: String = "citizen_identity"

    /**
     * Requests a refresh token for background/offline access.
     */
    public const val OFFLINE_ACCESS: String = "offline_access"
}
