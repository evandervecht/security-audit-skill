package com.example.crypto

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class TokenCipher(private val key: ByteArray) {
    fun encrypt(plaintext: ByteArray): ByteArray {
        // bare "AES" defaults to AES/ECB/PKCS5Padding on the JVM
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(plaintext)
    }

    fun encryptLegacy(plaintext: ByteArray): ByteArray {
        // ECB encrypts identical blocks identically - patterns leak
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(plaintext)
    }
}
