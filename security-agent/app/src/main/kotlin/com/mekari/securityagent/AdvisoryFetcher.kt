package com.mekari.securityagent

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * Optional, operator-enabled fetch of an external mobile-security advisory feed.
 * This is the CONTROLLER app's own egress; it is outside the target-UID scoped
 * firewall and does not weaken that containment. The returned text is untrusted
 * external data: the caller sanitizes it and the model treats it as reference
 * only, never as instructions. Failure is non-fatal (fail-open to no advisories).
 */
internal object AdvisoryFetcher {
    private const val MAX_ADVISORY_BYTES = 256 * 1024

    fun fetch(endpoint: String): String {
        val uri = URI(endpoint)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null) {
            "Advisory endpoint must be an HTTPS URI without user information or fragment"
        }
        val connection = (URL(uri.toASCIIString()).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = 10_000; readTimeout = 15_000; requestMethod = "GET"
            setRequestProperty("Accept", "text/plain, application/json")
        }
        try {
            val code = connection.responseCode
            if (code !in 200..299) throw IllegalStateException("Advisory feed returned HTTP $code")
            val output = java.io.ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(4096)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_ADVISORY_BYTES) throw IllegalStateException("Advisory feed exceeded size limit")
                    output.write(buffer, 0, count)
                }
            }
            return String(output.toByteArray(), Charsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }
}
