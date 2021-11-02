package com.globaltask.encript.rsa

import android.util.Base64
import com.globaltask.encript.aes.Aes
import com.globaltask.encript.base64ToByteArray
import com.globaltask.encript.toBase64
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE

class Rsa private constructor(private val aes: Aes) {

    private val transformation = "RSA/ECB/PKCS1PADDING"
    private val encryptType = "RSA";
    private val cipher by lazy { Cipher.getInstance(transformation) }
    private val keyFactory by lazy { KeyFactory.getInstance(encryptType) }

    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    companion object {

        @Volatile private var INSTANCE: Rsa? = null

        fun getInstance(aes: Aes): Rsa =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Rsa(aes).also { INSTANCE = it }
            }

    }

    fun code(message: String): String {
        cipher.init(ENCRYPT_MODE, publicKey)
        val encryptedMessageByteArray = cipher.doFinal(message.toByteArray())
        return encryptedMessageByteArray.toBase64()
    }

    fun decode(encrypted: String): String {
        cipher.init(DECRYPT_MODE, privateKey)
        val messageByteArray = cipher.doFinal(encrypted.base64ToByteArray())
        return String(messageByteArray)
    }

    fun setTemporaryEncryptedKeys(publicTemporaryEncryptedKey: String, privateEncryptedKey: String) {
        publicKey = aes.decode(publicTemporaryEncryptedKey, true)
            .let {
                val key = X509EncodedKeySpec(it.base64ToByteArray())
                keyFactory.generatePublic(key)
            }
        privateKey = aes.decode(privateEncryptedKey, true)
            .let {
                val key = PKCS8EncodedKeySpec(it.base64ToByteArray())
                keyFactory.generatePrivate(key)
            }
    }

}