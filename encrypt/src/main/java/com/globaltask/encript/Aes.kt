package com.globaltask.encript

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Aes(
    private val globalKey: String,
    private val hmacKey: String
) {
    companion object {

        // Constantes
        private const val algorithm = "HmacSHA256"
        private const val transformation = "AES/CBC/PKCS7PADDING"
        private const val hmacLength = 45
        private const val secureRandomLength = 25
        private const val secureRandomArraySize = 16
        private const val encryptType = "AES"
        private const val base64flag = Base64.DEFAULT

        private val cipher by lazy { Cipher.getInstance(transformation) }
        private val secureRandomArray by lazy { generateSecureRandomArray() }

        /**
         * Esta función genera un hash basado en en mensaje encriptado y una llave.
         * HMAC significa código de autenticación de mensajes basado en hash.
         * @param encrypted mensaje encriptado
         * @param key llave de cif  rado
         */
        fun generateHmac(encrypted: String, key: String): String {
            val sha256Hmac = Mac.getInstance(algorithm)
            val secretKey = SecretKeySpec(key.toByteArray(), algorithm)
            sha256Hmac.init(secretKey)
            return Base64.encodeToString(sha256Hmac.doFinal(encrypted.toByteArray()), base64flag)
        }

        /**
         * Esta función genera un array de números aleatorios con un nivel se seguridad
         * criptográfica
         */
        fun generateSecureRandomArray(): ByteArray {
            val secureRandom = SecureRandom()
            val result = ByteArray(secureRandomArraySize)
            secureRandom.nextBytes(result)
            return result
        }

    }

    /**
     * Esta función códifica un mensaje.
     * @param message mensaje a encriptar
     * @param hashEncrypt texto encriptado poseedor de la llave para general el hmac
     * @param symmetricalAccess texto encriptado poseedor de la llave simetrica de encriptación
     */
    fun code(message: String, hashEncrypt: String, symmetricalAccess: String): String {

        // Generación de un vector de bytes aleatorio.
//        val secureRandomArray = generateSecureRandomArray()

        // Se códifica el secureRandomArray a base64, para manejarlo como un String.
        val secureRandom = Base64.encodeToString(secureRandomArray, base64flag)

        // Vector de inicialización creado a partir de secureRandomArray.
        // Este valor es utilizado por cifrados con algortimos de retroalimentación como el AES.
        val iv = IvParameterSpec(secureRandomArray)

        // Desencriptación del parametro symmetricalAccess, para poder conseguir la llave de
        // encriptación simétrica
        val symmetricalKey = decode(symmetricalAccess, globalKey)

        // Creación de llave secreta a partir de una matriz de bytes dada y del algoritmo a utilizar
        val secretKey = SecretKeySpec(Base64.decode(symmetricalKey, base64flag), encryptType)

        // Encriptación del mensaje
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
        val encryptedArray = cipher.doFinal(message.toByteArray())
        val encrypted = Base64.encodeToString(encryptedArray, base64flag)

        // Desencriptación del parametro hashEncrypt, este valor sera utilizado como llave de cifrdo
        // para generar el hmac
        val hash = decode(hashEncrypt, globalKey)

        // El hmac es un hash que se calcula con el mensaje encriptado y su respectiva llave de
        // cifrado, dicho valor sera concatenado al String resultante.
        val hmac = generateHmac(secureRandom+encrypted, hash)
        println(">>: decode.hmac: ${hmac.length}")

        return (secureRandom + encrypted + hmac).replace("\n", "")
    }

    /**
     * Esta función decodifica un mensaje codificado
     * @param encoded mensaje codificado
     * @param key llave de decodificación, en caso de omitirse este parametro su valor pasa a ser el
     * del globalKey que se halla especificado en el constructor
     */
    fun decode(encoded: String, key: String = globalKey): String {

        // NOTA: El mensaje codificado esta compuesto por tres partes:
        // 1. secureRandom: Representacion en base64 de un vector de bytes aleatorio.
        // 2. encrypted: Mensaje encriptado.
        // 3. hmac: Hash obtenido con el mensaje encriptado y una llave de cifrado. La longitud del
        //    hmac ha demostrado poseer una longitud constante sin importar el tamaño del mensaje.

        // Obteniendo el secureRandom del codificado
        val secureRandom = encoded.substring(0, secureRandomLength - 1)


        // Obteniendo en mensaje encriptado del codificado
        val encrypted = encoded.substring(secureRandomLength-1, (encoded.length - (hmacLength - 1)))

        // obteniendo el hmac del codificado
        val hmac = encoded.substring((encoded.length - (hmacLength - 1)), encoded.length)

        // NOTA: No entiendo la razón de esta linea, dicho valor no vuelve a ser utilizado.
        // su unica finalizdad es para comprobar que sea diferente que el hmac extraido del mencaje
        // codificado. pero obvio que siempre sera diferente ya que el hmac del mensaje cifrado
        // utiliza una llave generadora que la de esta linea.
        // Tras lo ya mencionado la siguiente linea parece no tener utilidad alguna. ademas que
        // inutilizaria el uso del parametro hmacKey.
        val hmacGenerated = generateHmac(secureRandom+encrypted, hmacKey)

        // Esto siempre sera true
        if (hmac != hmacGenerated) {

            // Vector de inicialización creado a partir de secureRandomArray.
            // Este valor es utilizado por cifrados con algortimos de retroalimentación como el AES.
            val iv = IvParameterSpec(Base64.decode(secureRandom, base64flag))

            // Creación de llave secreta a partir de una matriz de bytes dada y del algoritmo a
            // utilizar
            val secretKey = SecretKeySpec(Base64.decode(key, base64flag), encryptType)

            // Desencriptación del mensaje
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
             val decryptedArray = cipher.doFinal(Base64.decode(encrypted, base64flag))
            return String(decryptedArray)

        } else {
            throw UnsupportedOperationException()
        }

    }

}