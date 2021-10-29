package com.globaltask.encript

import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    // INICIALIZACIÓN DE LAS PRUEBAS
    companion object  {

        // CONSTANTES
        private const val SECURITY_ENCRYPTION_SYMMETRIC_KEY = "DAgawS2KsZBRyElqMUOJhLiQqnVTvli4B59qm1XeSQM="
        private const val SECURITY_ENCRYPTION_HMACKEY       = "C73e7IZeeEhqQjXjJFf1ug=="

        // TEMPORALES ENCRIPTADAS
        private const val symmetricalKeyEncrypt = "Vxz7Z9EQPT+4L49nkjL9e+y18raDF7Djs/rL9Ip5NiWSuJrpCyyxX+YaO2LF4msM18Blcfoyue+WJuLCHuevp59oRnIkqDiTS+KlUCQpW81+UpsDpou1t8k8SRbb2D4O"
        private const val hmacKeyEncrypt = "aaYTSPen030xUN7+NmY5yw==JC2uBdJp19PVjqbg2M1XrraQLc4IxqM+TPlP0x/wrcM=wtirKYyGXqdRDILdFpj2TMnV8ndMfWHhFUoJMBqVQEI="

        // TEMPORALES DESENCRIPTDA
        private const val symmetricalKey = "DAgawS2KsZBRyElqMUOJhLiQqnVTvli4B59qm1XeSQM="
        private const val hmacKey = "C73e7IZeeEhqQjXjJFf1ug=="

        // CREANDO LA INSTANCIA DEL AES
        private val aes = Aes.getInstance(SECURITY_ENCRYPTION_SYMMETRIC_KEY, SECURITY_ENCRYPTION_HMACKEY)

    }

    @Test
    fun returnTrueIfCodeAndDecodeSuccess() {

        val originalMessage = "yolanda@yopmail.com"

        val encrypt = aes.code(originalMessage, hmacKey, symmetricalKey)
//        println(">>: encrypt: $encrypt")

//        val key = aes.decode(symmetricalKeyEncrypt, hmacKeyEncrypt)
//        println(">>: key: $key")

        val message = aes.decode(encrypt, hmacKey, symmetricalKey)
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

        val encrypt = symmetricalKeyEncrypt
        val expected = SECURITY_ENCRYPTION_SYMMETRIC_KEY

        val message = aes.decode(encrypt, hmacKey, symmetricalKey)
//        println(">>: message: $message")

        assertEquals(message, expected)

    }

}