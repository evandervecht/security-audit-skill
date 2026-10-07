package com.example.crypto

import java.security.PublicKey
import javax.crypto.Cipher

class KeyWrapper(private val publicKey: PublicKey) {
    fun wrap(contentKey: ByteArray): ByteArray {
        // "ECB" in an RSA transformation is a JCA naming artifact, not block-mode ECB
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(contentKey)
    }
}
