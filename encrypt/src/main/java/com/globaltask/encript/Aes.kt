package com.globaltask.encript

import android.util.Base64
import com.globaltask.encript.exceptions.CorruptMessageException
import com.globaltask.encript.exceptions.UndefinedTemporaryKeysException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Esta clase ofrece las funciones necesarias para codificar y decodificar mensajes encriptados con
 * AES.
 */
class Aes private constructor(globalKeySymmetrical: String, globalKeyHmac: String) {

    private val symmetricalKey = globalKeySymmetrical.base64ToByteArray()
    private val hmacKey = globalKeyHmac.base64ToByteArray()

    private var symmetricalTemporaryKey: ByteArray? = null
    private var hmacTemporaryKey: ByteArray? = null

    // CONSTANTES
    private val algorithm = "HmacSHA256"
    private val transformation = "AES/CBC/PKCS7PADDING"
    private val encryptType = "AES"
    private val hmacLength = 32 // Bytes
    private val secureRandomLength = 16 // Bytes
    private val base64flag = Base64.DEFAULT

    private val cipher by lazy { Cipher.getInstance(transformation) }
    private val ivByteArray by lazy { generateIv() }

    companion object {

        @Volatile private var INSTANCE: Aes? = null

        /**
         * Genera una instancia singleton de la clase Aes
         * @param globalKeySymmetrical llave con la cual se desencriptara la llave temporal simetrica.
         * @param globalKeyHmac llave con la cual se desencriptara la llave para generar el hmac
         */
        fun getInstance(globalKeySymmetrical: String, globalKeyHmac: String): Aes =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Aes(globalKeySymmetrical, globalKeyHmac).also { INSTANCE = it }
            }

    }

    /**
     * Esta función códifica un mensaje.
     * @param message mensaje a encriptar
     * @return mensaje encriptado
     */
    fun code(message: String): String {

        if (symmetricalTemporaryKey==null) throw UndefinedTemporaryKeysException()

        // Vector de inicialización
        val iv = IvParameterSpec(ivByteArray)

        // Llave de encriptación
        val key = SecretKeySpec(symmetricalTemporaryKey, encryptType)

        // Encriptación del mensaje
        cipher.init(ENCRYPT_MODE, key, iv)
        val encryptedMessageByteArray = cipher.doFinal(message.toByteArray())

        // Hmac obtenido a partir del iv y el mensaje encriptado
        val hmacByteArray = generateHmac(ivByteArray, encryptedMessageByteArray)

        return (ivByteArray + encryptedMessageByteArray + hmacByteArray).toBase64()

    }

    fun decode(encoded: String, useGlobalKeys: Boolean = false): String {

        val key = (if (useGlobalKeys) symmetricalKey else symmetricalTemporaryKey)
            ?: throw UndefinedTemporaryKeysException()

        val encodedByteArray = encoded.base64ToByteArray()

        // Obteniendo el secureRandom del codificado
        val ivByteArray = encodedByteArray.copyOfRange(0, secureRandomLength)

        // Obteniendo en mensaje encriptado del codificado
        val encryptedMessageByteArray = encodedByteArray.copyOfRange(secureRandomLength, (encodedByteArray.size - hmacLength))

        // obteniendo el hmac del codificado
        val hmacByteArray = encodedByteArray.copyOfRange((encodedByteArray.size - hmacLength), encodedByteArray.size)

        val hmac = generateHmac(ivByteArray, encryptedMessageByteArray, useGlobalKeys)

        if (!hmac.contentEquals(hmacByteArray)) throw CorruptMessageException()

        // Vector de inicialización creado a partir de secureRandomArray.
        // Este valor es utilizado por cifrados con algortimos de retroalimentación como el AES.
        val iv = IvParameterSpec(ivByteArray)

        // Creación de llave secreta a partir de una matriz de bytes dada y del algoritmo a
        // utilizar
        val secretKey = SecretKeySpec(key, encryptType)

        // Desencriptación del mensaje
        cipher.init(DECRYPT_MODE, secretKey, iv)
        val decryptedArray = cipher.doFinal(encryptedMessageByteArray)

        return String(decryptedArray)

    }

    fun setTemporaryEncryptedKeys(symmetricalTemporaryEncryptedKey: String, hmacTemporaryEncryptedKey: String) {
        symmetricalTemporaryKey = decode(symmetricalTemporaryEncryptedKey, true).base64ToByteArray()
        hmacTemporaryKey = decode(hmacTemporaryEncryptedKey, true).base64ToByteArray()
    }

    /**
     * Esta función genera un hmac según sus parametros de entrada.
     * HMAC significa código de autenticación de mensajes basado en hash.
     * dicho valor sera anexado al final del mensaje encriptado, y se suele utilizar como método de
     * deteccion de errores.
     * @param ivByteArray vector de inicialización
     * @param encryptedMessageByteArray mensje encriptado
     * @param key llave a utilizar para generar el hmac
     */
    private fun generateHmac(
        ivByteArray: ByteArray,
        encryptedMessageByteArray: ByteArray,
        useGlobalKeys: Boolean = false
    ): ByteArray {
        val key = (if (useGlobalKeys) hmacKey else hmacTemporaryKey)
            ?: throw UndefinedTemporaryKeysException()
        val concat = ivByteArray + encryptedMessageByteArray
        val sha256Hmac = Mac.getInstance(algorithm)
        val secretKey = SecretKeySpec(key, algorithm)
        sha256Hmac.init(secretKey)
        return sha256Hmac.doFinal(concat)
    }

    /**
     * Esta función genera un array de bytes con números aleatorios creados con un algoritmo que
     * garantiza una aliatoriedad con un nivel de seguridad criptografica.
     * Este valor es utilizado por cifrados con algortimos de retroalimentación como el AES.
     */
    private fun generateIv(): ByteArray {
        val secureRandom = SecureRandom()
        val result = ByteArray(secureRandomLength)
        secureRandom.nextBytes(result)
        return result
    }

    //<editor-fold desc="FUNCIONES DE EXTENSIÓN">

    /**
     * Función de extensión que facilita la conversion de ByteArray a base64
     */
    private fun ByteArray.toBase64(): String {
        return Base64.encodeToString(this, base64flag).replace("\n", "")
    }

    /**
     * Función de extensión que facilita la decodificacion de un texto en Base64 a ByteArray
     */
    private fun String.base64ToByteArray(): ByteArray {
        return Base64.decode(this, base64flag)
    }
    //</editor-fold>

}