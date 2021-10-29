package com.globaltask.encript

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Esta clase ofrece las funciones necesarias para codificar y decodificar mensajes encriptados con
 * AES.
 */
class Aes private constructor(
    private val globalKey: String,
    private val globalHmacKey: String
) {

    // CONSTANTES
    private val algorithm = "HmacSHA256"
    private val transformation = "AES/CBC/PKCS7PADDING"
    private val hmacLength = 32 // Bytes
    private val secureRandomLength = 16 // Bytes
    private val encryptType = "AES"
    private val base64flag = Base64.DEFAULT

    private val cipher by lazy { Cipher.getInstance(transformation) }
    private val ivByteArray by lazy { generateIv() }

    companion object {

        @Volatile private var INSTANCE: Aes? = null

        /**
         * Genera una instancia singleton de la clase Aes
         * @param globalKey llave con la cual se desencriptara la llave temporal simetrica.
         * @param hmacKey llave con la cual se desencriptara la llave para generar el hmac
         */
        fun getInstance(globalKey: String, hmacKey: String): Aes =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Aes(globalKey, hmacKey).also { INSTANCE = it }
            }

    }

    /**
     * Esta función códifica un mensaje.
     * @param message mensaje a encriptar
     * @param hmacKey llave para generar el hmac
     * @param symmetricalKey llave simetrica de encriptación
     */
    fun code(message: String, hmacKey: String, symmetricalKey: String): String {

        // Vector de inicialización
        val iv = IvParameterSpec(ivByteArray)

        // Llave de encriptación
        val key = SecretKeySpec(symmetricalKey.base64ToByteArray(), encryptType)

        // Encriptación del mensaje
        cipher.init(ENCRYPT_MODE, key, iv)
        val encryptedMessageByteArray = cipher.doFinal(message.toByteArray())

        // Hmac obtenido a partir del iv y el mensaje encriptado
        val hmacByteArray = generateHmac(ivByteArray, encryptedMessageByteArray, hmacKey)

        return (ivByteArray + encryptedMessageByteArray + hmacByteArray).toBase64()

    }

    /**
     * Esta función decodifica un mensaje codificado
     * @param encoded mensaje codificado
     * @param hmacKey llave para generar el hmac
     * @param key llave simetrica de encriptación, en caso de omitirse este parametro su valor pasa
     * a ser el  del globalKey que se halla especificado en el constructor
     */
    fun decode(encoded: String, hmacKey: String, key: String = globalKey): String {

        // NOTA: El mensaje codificado esta compuesto por tres partes:
        // 1. secureRandom: Representacion en base64 de un vector de bytes aleatorio.
        // 2. encrypted: Mensaje encriptado.
        // 3. hmac: Hash obtenido con el mensaje encriptado y una llave de cifrado. La longitud del
        //    hmac ha demostrado poseer una longitud constante sin importar el tamaño del mensaje.

        val encodedByteArray = encoded.base64ToByteArray()

        // Obteniendo el secureRandom del codificado
        val secureRandomByteArray = encodedByteArray.copyOfRange(0, secureRandomLength)

        // Obteniendo en mensaje encriptado del codificado
        val encryptedByteArray = encodedByteArray.copyOfRange(secureRandomLength, (encodedByteArray.size - hmacLength))

        // obteniendo el hmac del codificado
        val hmacByteArray = encodedByteArray.copyOfRange((encodedByteArray.size - (hmacLength - 1)), encodedByteArray.size)

        // TODO: Crear funcion para comprobación de errores

        // Vector de inicialización creado a partir de secureRandomArray.
        // Este valor es utilizado por cifrados con algortimos de retroalimentación como el AES.
        val iv = IvParameterSpec(secureRandomByteArray)

        // Creación de llave secreta a partir de una matriz de bytes dada y del algoritmo a
        // utilizar
        val secretKey = SecretKeySpec(Base64.decode(key, base64flag), encryptType)

        // Desencriptación del mensaje
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
        val decryptedArray = cipher.doFinal(encryptedByteArray)

        return String(decryptedArray)

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
    private fun generateHmac(ivByteArray: ByteArray, encryptedMessageByteArray: ByteArray, key: String): ByteArray {
        val concat = ivByteArray + encryptedMessageByteArray
        val sha256Hmac = Mac.getInstance(algorithm)
        val secretKey = SecretKeySpec(key.toByteArray(), algorithm)
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