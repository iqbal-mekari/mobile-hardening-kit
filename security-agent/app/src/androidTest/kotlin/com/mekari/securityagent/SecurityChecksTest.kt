package com.mekari.securityagent

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
class SecurityChecksTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun installedManifestProducesMetadataEvidence() {
        val config = SessionConfig(
            targetPackage = context.packageName,
            endpoint = "https://example.invalid/v1",
            model = "test",
            allowedHosts = listOf("example.invalid")
        )
        val result = SecurityChecks(context, RootShell()).run("manifest", config)
        assertEquals("manifest", result.checkId)
        assertEquals("complete", result.status)
        assertTrue(result.summary.contains("versionCode="))
        assertTrue(result.summary.contains("exportedComponents="))
    }

    @Test
    fun unsupportedCheckIsExplicitlyUnavailable() {
        val config = SessionConfig(context.packageName, "https://example.invalid/v1", "test", listOf("example.invalid"))
        val result = SecurityChecks(context, RootShell()).run("tls_decryption", config)
        assertEquals("unavailable", result.status)
        assertTrue(result.summary.contains("Unsupported"))
    }

    @Test
    fun coverageNamesUnsupportedRuntimeInspection() {
        val config = SessionConfig(context.packageName, "https://example.invalid/v1", "test", listOf("example.invalid"))
        val result = SecurityChecks(context, RootShell()).run("coverage", config)
        assertEquals("incomplete", result.status)
        assertTrue(result.summary.contains("decrypted network traffic"))
        assertTrue(result.summary.contains("cross-account/business-logic"))
    }

    @Test
    fun exactHostPolicyRejectsScopeExpansionInputs() {
        ScopedFirewall.validateHostInput("staging.example")
        ScopedFirewall.validateHostInput("192.0.2.1")
        ScopedFirewall.validateHostInput("2001:db8::1")
        listOf("", "*.staging.example", "https://staging.example/path", "user@staging.example", " staging.example", "staging.example\n").forEach { input ->
            try {
                ScopedFirewall.validateHostInput(input)
                throw AssertionError("Invalid exact host was accepted")
            } catch (_: IllegalArgumentException) {
                // Expected: the firewall input policy rejects ambiguous or expandable scopes.
            }
        }
    }
}
