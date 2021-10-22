package com.example.pruebaaes2

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.security.*
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


//var iv = "Ve7GDmoZlekzjXdHQMxT3w==".toByteArray(charset("US-ASCII"))
//val key = "bbC2H19lkVbQDfakxcrtNMQdd0FloLyw"
//var playtext = "dato+encriptado+url+encode=="
//var algorithm = "aes-128-cbc"
//Instanciamos un objeto de cifrado de tipo AES
//val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
//BASE64 formato de codificacion y decodificacion
//var encodedKey: ByteArray = Base64.decode(key, Base64.DEFAULT)
//var originalKey: SecretKey = SecretKeySpec(encodedKey, 0, encodedKey.size, "AES")

var stringConcatenate =
    "A45pFeUyNBMvdcuKFDi8xA==1imeT0NhPqYWgzn95VfviB7wpMZRE+bswQU5Czt6eoo=+vmMTXoo4udr+dtsjoNKa7Q7ekw72EvWXH9usJDFXpY="
val GLOBAL_SYMMETRIC_KEY =
    "1dNpH6j58Ry9bBFeDMotmQ=="
val HMAC_ENCRYPTION_KEY =
    "RabtLEt2b4CDYtprp1zBtPiMyulxfVx40cR5HYtyHyCVSG0wV2udbtxfHW2Xw5d08DLjERtacpPyP1EbfS3AUvvzNWyZmUu+eoJ85xkAF8wDgFdmR9+UYxc1xd0Yt9ghzf1S6sR1It4pqsMBmKGG8uXc/mXfsSl97g6v7kLlHDA="
val algorithm =
    "HmacSHA256"
val simetricAccess =
    "cTly/7xz2GKu7jJBeDd1nA==vmb/pWfW+00jl1/L7Euacf9Xw0BUVwn3HzNjKBHcc2Y=ATvZuS8gWlAf7NCfFcVDR7BvbqKXouKASlDung69NT4="
val hashEncrypt =
    "cTly/7xz2GKu7jJBeDd1nA==KNpVhpJuVUV4RQuc9tosMsUYvGkZYJWdwykZHJDeqvyf72IFCyuxkhvdaOM56uZsH7+rl/SM9dfAvWyDmN+xwtwjUnkjs/X4iWUJvvNw19TaU5RT6i/OJ/CjazOemvLKY2aNVP06l46cY6dhlP3yVwmdhWkH6PtnlqDtypgI5LRP7bQzY8tFQJU2Y+HKbUPIaM5Q5rSTlyyGxUWJBGe+Ceda/sF2gQmnVOhhOhLh5pQ=9s4QR0wo05fS574+E1K6RzsVa+VddwEoe+OEN/NwK9E="

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
//        val encrypt = encrypt(playtext.toByteArray(), originalKey, iv)
//        val encryptText = String(encrypt!!, charset("UTF-8"))
//        Log.d("TAG", encryptText)

//        val decryptt = decrypt(stringConcatenate, secretKey)
//        if (decryptt != null) {
//            Log.d("TAG2", decryptt)
//        }5
//        val decryptHash = decrypt(
//            hashEncrypt,
//            secretKey
//        )

        //obtengo la clave simetrica que usare para encriptar y desencriptar todos los campos AES
        val simetricKey = decrypt(simetricAccess, GLOBAL_SYMMETRIC_KEY)
        if (simetricKey != null) {
            val encryptValue =
                encrypt("yolanda@yopmail.com", simetricAccess, hashEncrypt, simetricKey)
            val decryptt = encryptValue?.let { decrypt(it, simetricKey) }
            if (decryptt != null) {
                Log.d("TAG2", decryptt)
            }
        }
    }
}

@Throws(Exception::class)
fun encrypt(
    decryptValue: String,
    simetricAccess: String,
    hashEncrypt: String,
    simetricKey: String
): String? {

    try {
        //genero un iv random
        val generatedIv = generateIv()
        val ivRandomBase64String = Base64.encodeToString(generatedIv, Base64.DEFAULT)
        val IvParameterSpec = IvParameterSpec(generatedIv)
//        val randomIvString = randomIv.toString()
//        val randomIv64 = Base64.encodeToString(randomIvString.toByteArray(),Base64.DEFAULT)

//        val ivParameterSpec =
//            IvParameterSpec(Base64.decode(randomIv.T, Base64.DEFAULT))
        //decodeo la simetric key que llega por parametro
        val simetricKeyDecode = Base64.decode(simetricKey, Base64.DEFAULT)
        val simetricKeySpec = SecretKeySpec(simetricKeyDecode, "AES")
        //Obtengo el hmac desencryptado
        val hashDecrypt = decrypt(hashEncrypt, GLOBAL_SYMMETRIC_KEY)
        //Instanciamos un objeto de cifrado de tipo AES
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, simetricKeySpec, IvParameterSpec)
        val encryptedText = cipher.doFinal(decryptValue.toByteArray())
        val encrytedTextBase64 = Base64.encodeToString(encryptedText, Base64.DEFAULT)
        //generar hmac con la data ya encriptada. para luego concatenarla // el bloque de codigo solo se ejecuta si el objeto no es nullo
        val hMac = hashDecrypt?.let { generateHmac(encrytedTextBase64, it, algorithm) }
        //concatenar valores
        val encryptValue = (ivRandomBase64String + encrytedTextBase64 + hMac).replace("\n", "")
        return encryptValue

    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
    } catch (e: NoSuchPaddingException) {
        e.printStackTrace()
    } catch (e: InvalidKeyException) {
        e.printStackTrace()
    } catch (e: IllegalBlockSizeException) {
        e.printStackTrace()
    } catch (e: BadPaddingException) {
        e.printStackTrace()
    } catch (e: InvalidAlgorithmParameterException) {
        e.printStackTrace()
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return null
}


fun decrypt(encryptValue: String, secreyKey: String): String? {
    try {
        //obtener el lenght del hmac random para restarselo al texto original
        val hmacBase64Lengh = generateHmac("random", HMAC_ENCRYPTION_KEY, algorithm).length - 1
        //obtengo el largo del iv y texto cifrado
        val ivCipherTextLength = encryptValue.length - hmacBase64Lengh
        //obtengo el iv y el texto cifrado
        val ivCipherText = encryptValue.substring(0, ivCipherTextLength)
        //convierto el iv generado aleatoriamente en base 64
        val ivRandomBase64 = Base64.encodeToString(generateIv(), Base64.DEFAULT)
        //obtengo el IV que viene por parametro concatenado (original)
        val iv = ivCipherText.substring(0, ivRandomBase64.length - 1)
        //Obtengo el texto cifrado
        val textCiphered = encryptValue.substring(iv.length, ivCipherText.length)
        //obtengo el HASH recibido en el string
        val hmacReceive = encryptValue.substring(ivCipherTextLength, encryptValue.length)
        //obtengo el HMAC del string que viene por parametro ya cortado
        val hmacGenerated =
            generateHmac(textCiphered, HMAC_ENCRYPTION_KEY, algorithm).replace("\n", "")
        //El operador !== devuelve verdadero cuando los elementos no tienen el mismo valor o el mismo tipo.
        if (hmacReceive !== hmacGenerated) {
            //Construimos una clave secreta indicandole que es de tipo AES pasandole el string decodeado en base64, actualmente esta en base64
            // pero lo lee como utf-8 porque viene como string1q
            val secretKeySpec = SecretKeySpec(Base64.decode(secreyKey, Base64.DEFAULT), "AES")
            // Pasamos el Iv a tipo IvParameterSpec, pero antes lo docodeo transformando el iv que tengo como stringq    que por defecto lo lee een
            //UTF-8 en base64, para que pueda convertirse a 16bytes
            val ivParameterSpec = IvParameterSpec(Base64.decode(iv, Base64.DEFAULT))
            //Instanciamos un objeto de cifrado de tipo AES
            val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
            //Inicializamos el sistema de cifrado en modo Encriptacion con nuestra clave que hemos creado antes
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
            val decryptedText = cipher.doFinal(Base64.decode(textCiphered, Base64.DEFAULT))
            return String(decryptedText)
        } else {
            throw UnsupportedOperationException()
        }
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
    } catch (e: NoSuchPaddingException) {
        e.printStackTrace()
    } catch (e: InvalidKeyException) {
        e.printStackTrace()
    } catch (e: IllegalBlockSizeException) {
        e.printStackTrace()
    } catch (e: BadPaddingException) {
        e.printStackTrace()
    } catch (e: InvalidAlgorithmParameterException) {
        e.printStackTrace()
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return null
}

fun generateIv(): ByteArray {
    val secureRandom = SecureRandom()
    val result = ByteArray(128 / 8)
    secureRandom.nextBytes(result)
    return result
}


//HMAC significa código de autenticación de mensajes basado en hash.
//Esta autenticación es producto de una función hash aplicada al cuerpo }
// de un mensaje junto con una clave secreta.
fun generateHmac(data: String, key: String, algorithm: String): String {
    try {
        val sha256Hmac = Mac.getInstance(algorithm)
        val secretKey = SecretKeySpec(key.toByteArray(), algorithm)
        sha256Hmac.init(secretKey)
        return Base64.encodeToString(sha256Hmac.doFinal(data.toByteArray()), Base64.DEFAULT)
    } catch (e: NoSuchAlgorithmException) {
        throw IllegalStateException(e)
    } catch (e: InvalidKeyException) {
        throw IllegalArgumentException(e)
    }
}


//@Throws(NoSuchAlgorithmException::class)
//private fun getSecretKey(secret: String): SecretKeySpec? {
//    var key: ByteArray = secret.toByteArray(UTF_8)
//    val sha: MessageDigest = MessageDigest.getInstance("SHA256")
//    key = sha.digest(key)
//    key = Arrays.copyOf(key, 16)
//    return SecretKeySpec(key, "AES")
//}
