package com.globaltask.encript

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    companion object  {

        private const val GLOBAL_SYMMETRIC_KEY = "1dNpH6j58Ry9bBFeDMotmQ=="
        private const val HMAC_ENCRYPTION_KEY = "RabtLEt2b4CDYtprp1zBtPiMyulxfVx40cR5HYtyHyCVSG0wV2udbtxfHW2Xw5d08DLjERtacpPyP1EbfS3AUvvzNWyZmUu+eoJ85xkAF8wDgFdmR9+UYxc1xd0Yt9ghzf1S6sR1It4pqsMBmKGG8uXc/mXfsSl97g6v7kLlHDA="

        val symmetricAccess = "cTly/7xz2GKu7jJBeDd1nA==vmb/pWfW+00jl1/L7Euacf9Xw0BUVwn3HzNjKBHcc2Y=ATvZuS8gWlAf7NCfFcVDR7BvbqKXouKASlDung69NT4="
        val hashEncrypt = "cTly/7xz2GKu7jJBeDd1nA==KNpVhpJuVUV4RQuc9tosMsUYvGkZYJWdwykZHJDeqvyf72IFCyuxkhvdaOM56uZsH7+rl/SM9dfAvWyDmN+xwtwjUnkjs/X4iWUJvvNw19TaU5RT6i/OJ/CjazOemvLKY2aNVP06l46cY6dhlP3yVwmdhWkH6PtnlqDtypgI5LRP7bQzY8tFQJU2Y+HKbUPIaM5Q5rSTlyyGxUWJBGe+Ceda/sF2gQmnVOhhOhLh5pQ=9s4QR0wo05fS574+E1K6RzsVa+VddwEoe+OEN/NwK9E="

        private val aes = Aes(GLOBAL_SYMMETRIC_KEY, HMAC_ENCRYPTION_KEY)
    }

    /**
     * Esta función prueba que el resultado obtenido de la función generateHmac tenga siempre la
     * misma longitud.
     *
     * En caso de la prueba dar true, se puede asumir que el valor de hmac es constante. y usarlo
     * como constante.
     */
    @Test
    fun returnTrueIfgHmacResultLengthIsConst() {

        // PROBANDO LA LONGITUD DE LA RESPUESTA PARA UN TEXTO VACIO
        val s1 = ""
        val r1 = Aes.generateHmac(s1, HMAC_ENCRYPTION_KEY)
        println(">>: r1: { length:  ${r1.length}, r1: $r1 }")

        // PROBANDO LA LONGITUD DE LA RESPUESTA PARA UN TEXTO PEQUEÑO
        val s2 = "hola mundo"
        val r2 = Aes.generateHmac(s2, HMAC_ENCRYPTION_KEY)
        println(">>: r2: { length:  ${r2.length}, r2: $r2 }")

        if (r1.length!=r2.length) assertTrue(false)

        // PROBANDO LA LONGITUD DE LA RESPUESTA PARA UN TEXTO GRANDE
        val s3 = "RabtLEt2b4CDYtprp1zBtPiMyulxfVx40cR5HYtyHyCVSG0wV2udbtxfHW2Xw5d08DLjERtacpPyP1EbfS3AUvvzNWyZmUu+eoJ85xkAF8wDgFdmR9+UYxc1xd0Yt9ghzf1S6sR1It4pqsMBmKGG8uXc/mXfsSl97g6v7kLlHDA="
        val r3 = Aes.generateHmac(s3, HMAC_ENCRYPTION_KEY)
        println(">>: r3: { length:  ${r3.length}, r3: $r3 }")

        assertEquals(r2.length, r3.length)

    }

    /**
     * esta prueba falla, en caso de que la longitud del resultado de la función generateHmac sea
     * diferente a 44.
     */
    @Test
    fun returnTrueIfgHmacResultLengthIs44() {
        val r = Aes.generateHmac("", HMAC_ENCRYPTION_KEY)
        assertEquals(r.length, 44)
    }

    /**
     * esta prueba falla, en caso de que la longitud del resultado de la función
     * generateSecureRandomArray sea diferente a 25.
     */
    @Test
    fun returnTrueIfSecureRandomLengthIs25() {
        val secureRandomArray = Aes.generateSecureRandomArray()
        val secureRandom = Base64.encodeToString(secureRandomArray, Base64.DEFAULT)
        assertEquals(secureRandom.length, 25)
    }

    @Test
    fun returnTrueIfCodeAndDecodeSuccess() {

        val originalMessage = "Hola mundo"

        val encrypt = aes.code(originalMessage, hashEncrypt, symmetricAccess)
//        println(">>: encrypt: $encrypt")

        val key = aes.decode(symmetricAccess)
//        println(">>: key: $key")

        val message = aes.decode(encrypt, key)
//        println(">>: message: $message")

        assertEquals(message, originalMessage)
    }

    /**
     * Esta es la prueba definitiva para constatar que se es capaz de decifrar un mensaje encriptado
     * desde el servidor.
     *
     * INSTRUCCIONES PARA LA PRUEBA.
     *
     * Para los valores de GLOBAL_SYMMETRIC_KEY, HMAC_ENCRYPTION_KEY, symmetricAccess y hashEncrypt,
     * conocidos, se debe proporcionar un mensaje encriptado desde el servidor, junto con su valor
     * no encriptado.
     *
     * Esta prueba debera ser capaz de decifrar dicho mensaje encriptado y obtener el valor esperado.
     */
    @Test
    fun returnTrueIfRemoteMessageIfDecode() {

        val encrypt = ""
        val expected = ""

        val key = aes.decode(symmetricAccess)

        val message = aes.decode(encrypt, key)

        assertEquals(message, expected)

    }

}