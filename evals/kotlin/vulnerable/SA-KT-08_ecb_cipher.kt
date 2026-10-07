package com.example.crypto

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class FieldEncryptor(secret: ByteArray) {
    private val key = SecretKeySpec(secret, "AES")

    fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(plaintext)
    }

    fun encryptLegacy(plaintext: ByteArray): ByteArray {
        // Bare "AES" silently defaults to ECB mode
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(plaintext)
    }
}
