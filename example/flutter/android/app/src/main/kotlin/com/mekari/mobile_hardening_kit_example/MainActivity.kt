package com.mekari.mobile_hardening_kit_example

import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.MessageDigest

class MainActivity : FlutterActivity() {
    private var channel: MethodChannel? = null
    private var pendingResult: MethodChannel.Result? = null
    private var tokenProvider: StandardIntegrityTokenProvider? = null
    private var providerProjectNumber: Long? = null
    private var attached = false

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        attached = true
        channel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CHANNEL_NAME
        ).also { methodChannel ->
            methodChannel.setMethodCallHandler { call, result ->
                if (call.method != "requestToken") {
                    result.notImplemented()
                    return@setMethodCallHandler
                }
                requestToken(call.arguments, result)
            }
        }
    }

    private fun requestToken(arguments: Any?, result: MethodChannel.Result) {
        if (!attached) {
            result.error("activity_detached", "The Android activity is unavailable.", null)
            return
        }
        if (pendingResult != null) {
            result.error("request_in_progress", "A token request is already in progress.", null)
            return
        }
        val values = arguments as? Map<*, *>
        val rawProjectNumber = values?.get("cloudProjectNumber")
        val projectNumber = when (rawProjectNumber) {
            is Byte -> rawProjectNumber.toLong()
            is Short -> rawProjectNumber.toLong()
            is Int -> rawProjectNumber.toLong()
            is Long -> rawProjectNumber
            else -> null
        }
        val payload = values?.get("requestPayload") as? String
        if (projectNumber == null || projectNumber <= 0L || payload.isNullOrEmpty()) {
            result.error("invalid_arguments", "A valid project number and request payload are required.", null)
            return
        }

        val requestHash = try {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(payload.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (_: Exception) {
            clearTokenProvider()
            result.error("hash_failed", "Unable to prepare the integrity request.", null)
            return
        }

        pendingResult = result
        val preparedProvider = tokenProvider
        if (preparedProvider != null && providerProjectNumber == projectNumber) {
            requestIntegrityToken(preparedProvider, requestHash, result)
            return
        }
        clearTokenProvider()
        try {
            val manager = IntegrityManagerFactory.createStandard(applicationContext)
            manager.prepareIntegrityToken(
                PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(projectNumber).build()
            ).addOnSuccessListener { provider ->
                if (!isCurrentRequest(result)) return@addOnSuccessListener
                tokenProvider = provider
                providerProjectNumber = projectNumber
                requestIntegrityToken(provider, requestHash, result)
            }.addOnFailureListener { error ->
                fail(result, error)
            }
        } catch (error: Exception) {
            fail(result, error)
        }
    }

    private fun requestIntegrityToken(
        provider: StandardIntegrityTokenProvider,
        requestHash: String,
        result: MethodChannel.Result
    ) {
        try {
            provider.request(
                StandardIntegrityTokenRequest.builder()
                    .setRequestHash(requestHash)
                    .build()
            ).addOnSuccessListener { response ->
                complete(result) { it.success(mapOf("token" to response.token())) }
            }.addOnFailureListener { error ->
                fail(result, error)
            }
        } catch (error: Exception) {
            fail(result, error)
        }
    }

    private fun clearTokenProvider() {
        tokenProvider = null
        providerProjectNumber = null
    }

    private fun isCurrentRequest(result: MethodChannel.Result): Boolean =
        attached && pendingResult === result

    private fun complete(result: MethodChannel.Result, callback: (MethodChannel.Result) -> Unit) {
        if (!isCurrentRequest(result)) return
        pendingResult = null
        callback(result)
    }

    private fun fail(result: MethodChannel.Result, error: Exception) {
        if (!isCurrentRequest(result)) return
        clearTokenProvider()
        val code = (error as? StandardIntegrityException)?.errorCode
        complete(result) {
            it.error(
                code?.let { "play_integrity_$it" } ?: "play_integrity_error",
                "Play Integrity token request failed${code?.let { " (code $it)" } ?: ""}.",
                null
            )
        }
    }

    override fun onDestroy() {
        pendingResult?.let {
            pendingResult = null
            it.error("activity_detached", "The Android activity was detached during the token request.", null)
        }
        attached = false
        clearTokenProvider()
        channel?.setMethodCallHandler(null)
        channel = null
        super.onDestroy()
    }

    private companion object {
        const val CHANNEL_NAME = "mobile_hardening_kit_example/play_integrity"
    }
}
