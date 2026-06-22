package krd.pass.auth

/**
 * Standard OAuth2 scopes supported by KRDPass.
 */
object KrdpassScopes {
    /**
     * Required for OpenID Connect flows. Returns the 'sub' claim.
     */
    const val OPENID = "openid"

    /**
     * Returns standard profile claims (name, family_name, given_name, picture).
     */
    const val PROFILE = "profile"

    /**
     * Returns digital identity claims (citizen_id, birthdate, etc.).
     */
    const val CITIZEN_IDENTITY = "citizen_identity"

    /**
     * Requests a refresh token for background/offline access.
     */
    const val OFFLINE_ACCESS = "offline_access"
}
