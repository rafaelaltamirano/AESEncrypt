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
        private const val SECURITY_ENCRYPTION_HMACKEY = "C73e7IZeeEhqQjXjJFf1ug=="

        // TEMPORALES ENCRIPTADAS
        private const val symmetricalTemporaryEncryptedKey = "LqjjKMA5HNYxUMUS4UQnQa2c6heYJqlYIKFpUN7O3dqoEJVpOtmdS98sk8w8K287tQeSdrtATPTkNmXCPcaWlTxknyHKLWKojXbpIu2MkJqC6QQ1MzoNEgrxmDuZNQfH"
        private const val hmacTemporaryEncryptedKey = "ixzbzllN5C94oKPArl57dpC3uy/ePs01tWSoV0EcM/ZlJzAvTqeJ4gD4BkFJEFVVKUVCyvqZ077tGHvSjuD+c8Rm3aXsLtIwB23fH7Jnli4="

        // YOLANDA@YOPMAIL.COM
        val mensaje = "bH5Cnott9d1EhzftUjkDm/b7d8YCUw43ThQd92IkgiLBaUAHbPSuOfRR0eFXkHOqtwH2VTSecgRgATIa+ktD8Q0j+pMPoSGTHsItrQ/brOw="

        // TEMPORALES DESENCRIPTDA
        private const val symmetricalKey = "DAgawS2KsZBRyElqMUOJhLiQqnVTvli4B59qm1XeSQM="
        private const val hmacKey = "C73e7IZeeEhqQjXjJFf1ug=="

        // CREANDO LA INSTANCIA DEL AES
        private val aes = Aes.getInstance(SECURITY_ENCRYPTION_SYMMETRIC_KEY, SECURITY_ENCRYPTION_HMACKEY)

    }

    @Test
    fun returnTrueIfCodeAndDecodeSuccess() {

        aes.setTemporaryEncryptedKeys(symmetricalTemporaryEncryptedKey, hmacTemporaryEncryptedKey)

        val originalMessage = "yolanda@yopmail.com"

        val encrypt = aes.code(originalMessage)

        val message = aes.decode(encrypt)

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

        aes.setTemporaryEncryptedKeys(symmetricalTemporaryEncryptedKey, hmacTemporaryEncryptedKey)

        val encrypt = "r91RBh5PjB/Dit4AlDEO6tpGoReeJMMaqZdXsdy6e30iNc1dKP4fxMeCFwLqfS/yWyjwJ+nBHrls7+95WQlnpA1NIlqf600eVOjIZHgMVFQ="
        val expected = "yelena@yopmail.com"

        val message = aes.decode(encrypt)

        assertEquals(message, expected)

    }

}