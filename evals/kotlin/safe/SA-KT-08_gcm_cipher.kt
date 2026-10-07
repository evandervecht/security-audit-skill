package com.example.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class FieldEncryptor(secret: ByteArray) {
    private val key = SecretKeySpec(secret, "AES")
    private val rng = SecureRandom()

    fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = ByteArray(12)
        rng.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(plaintext)
    }
}
