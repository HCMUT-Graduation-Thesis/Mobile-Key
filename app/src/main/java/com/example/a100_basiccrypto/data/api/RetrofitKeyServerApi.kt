package com.example.a100_basiccrypto.data.api

import com.example.a100_basiccrypto.data.model.*
import retrofit2.Response
import retrofit2.http.*

interface RetrofitKeyServerApi {
    
    // --- AUTH ---
    
    @POST("auth/login")
    suspend fun login(@Body request: LoginRequest): Response<AuthResponse>
    
    @GET("auth/me")
    suspend fun getMe(@Header("Authorization") token: String): Response<MeResponse>
    
    @POST("auth/refresh")
    suspend fun refresh(@Body request: RefreshRequest): Response<AuthResponse>
    
    // --- SHARING ---
    
    @POST("sharing/check-legality")
    suspend fun checkLegality(@Body request: ShareCheckRequest): Response<ShareCheckResponse>
    
    @POST("sharing/invite")
    suspend fun invite(@Body request: ShareInviteRequest): Response<ShareInviteResponse>
    
    @GET("sharing/pending")
    suspend fun fetchPendingInvitations(): Response<List<InvitationDetail>>
    
    @POST("sharing/claim")
    suspend fun claimInvitation(@Body request: ShareClaimRequest): Response<InvitationDetail>
    
    @POST("sharing/report-outcome")
    suspend fun reportOutcome(@Body report: ShareOutcomeReport): Response<Boolean>
    
    // --- REVOCATION ---
    
    @POST("revoke/friend")
    suspend fun revokeFriend(@Body request: RevokeFriendRequest): Response<RevokeFriendResponse>
    
    @GET("revoke/jobs")
    suspend fun fetchRevokeJobs(): Response<RevokeJobsResponse>
    
    @POST("revoke/jobs/report")
    suspend fun reportRevokeJob(@Body report: RevokeJobReport): Response<Boolean>
    
    // --- SYNC ---
    
    @POST("sync/upload")
    suspend fun uploadKey(@Body request: SyncKeyRequest): Response<SyncKeyResponse>
    
    @GET("sync/list")
    suspend fun fetchKeysList(): Response<List<SyncKeyDetail>>
}
