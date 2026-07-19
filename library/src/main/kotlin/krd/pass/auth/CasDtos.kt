package krd.pass.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire DTOs for the structured CAS/OAuth responses, decoded with kotlinx.serialization
 * (`ignoreUnknownKeys`). Required fields are nullable so the caller can fail-closed on a
 * malformed/empty response rather than trusting a silently-coerced default.
 */

/** `POST /connect/par` success body. */
@Serializable
internal data class ParResponseDto(
    @SerialName("request_uri") val requestUri: String? = null,
    @SerialName("expires_in") val expiresIn: Int = 300,
)

/** `POST /connect/token` success body (authorization_code + refresh_token grants). */
@Serializable
internal data class TokenResponseDto(
    @SerialName("access_token") val accessToken: String? = null,
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("token_type") val tokenType: String = "Bearer",
    @SerialName("expires_in") val expiresIn: Int = 3600,
    @SerialName("refresh_token") val refreshToken: String? = null,
    val scope: String? = null,
)

/** OAuth error body (`{ "error": ..., "error_description": ... }`). */
@Serializable
internal data class CasErrorDto(
    val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
)
