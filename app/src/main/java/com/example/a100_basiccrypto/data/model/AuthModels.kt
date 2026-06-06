package com.example.a100_basiccrypto.data.model

/**
 * Request body for Login API.
 */
data class LoginRequest(
    val email: String,
    val password: String,
    val identity_pk: String,
    val deviceName: String? = null,
    val displayName: String? = null,
    val fcmToken: String? = null
)

/**
 * Success response for Login and Refresh APIs.
 */
data class AuthResponse(
    val message: String,
    val accessToken: String,
    val refreshToken: String? = null, // Optional for Refresh API
    val user: UserResponse,
    val device: DeviceResponse? = null,
    val cloudPublicKey: String? = null
)

data class UserResponse(
    val id: String,
    val email: String,
    val display_name: String,
    val role: String
)

data class DeviceResponse(
    val id: String,
    val identity_pk: String,
    val device_name: String,
    val fcm_token: String?,
    val last_active: String?
)

/**
 * Request body for Token Refresh API.
 */
data class RefreshRequest(
    val refreshToken: String
)

/**
 * Response for GET /auth/me
 */
data class MeResponse(
    val user: UserResponse,
    val devices: List<DeviceResponse>,
    val cloudPublicKey: String
)
