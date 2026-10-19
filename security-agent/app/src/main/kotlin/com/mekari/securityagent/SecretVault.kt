package com.mekari.securityagent

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Device-local AES/GCM secret storage; secret identifiers are authenticated as AAD. */
internal class SecretVault(private val directory: File, private val keyAlias: String = "security_agent_secrets_v1") {
    private val allowedIds = setOf("cloud_api_key", "username", "password")

    @Synchronized fun set(id: String, value: String) {
        require(id in allowedIds && value.isNotEmpty() && value.length <= 4096)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
        val encrypted = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        atomicWrite(File(directory, "$id.enc"), Base64.encodeToString(encrypted, Base64.NO_WRAP))
    }

    @Synchronized fun get(id: String): String? {
        require(id in allowedIds)
        val file = File(directory, "$id.enc")
        if (!file.exists()) return null
        return try {
            require(file.length() in 1..32_768) { "Stored secret has invalid size" }
            val bytes = Base64.decode(file.readText(), Base64.NO_WRAP)
            require(bytes.size > 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
            cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
            String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)
        } catch (_: Exception) {
            throw IllegalStateException("Stored secret is corrupt or unavailable")
        }
    }

    private fun secretKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    private fun atomicWrite(target: File, value: String) {
        val temp = File.createTempFile("security-secret-", ".tmp", target.parentFile)
        try {
            FileOutputStream(temp).use { stream -> stream.write(value.toByteArray(Charsets.UTF_8)); stream.fd.sync() }
            if (!temp.renameTo(target)) throw IllegalStateException("Atomic secret persistence failed")
        } finally { if (temp.exists()) temp.delete() }
    }
}
