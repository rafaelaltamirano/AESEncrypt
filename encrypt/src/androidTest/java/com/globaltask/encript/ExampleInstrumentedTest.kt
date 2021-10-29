package com.globaltask.encript

import android.util.Base64
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

        // TEMPORALES
        private const val symmetricAccess = "ytSClhybDvRDgRmpn1b1bw==hjB4EcJst28m42fNgr0DoNTT+e+6SeIMxWaw7TT5n85imzxNnpkMdWLEKjU1tMVpWR+4a+5SZ0bItzBe7DSx02Je4GIYoBTNLrqWrsdU8KU="
        private const val hashEncrypt = "aaYTSPen030xUN7+NmY5yw==JC2uBdJp19PVjqbg2M1XrraQLc4IxqM+TPlP0x/wrcM=wtirKYyGXqdRDILdFpj2TMnV8ndMfWHhFUoJMBqVQEI="

        // CREANDO LA INSTANCIA DEL AES
        private val aes = Aes.getInstance(SECURITY_ENCRYPTION_SYMMETRIC_KEY, SECURITY_ENCRYPTION_HMACKEY)

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
        val s1 = "LAKSDFHSO"
        val r1 = aes.generateHmac(s1, hashEncrypt)
        println(">>: r1: { length:  ${r1.length}, r1: $r1 }")

        // PROBANDO LA LONGITUD DE LA RESPUESTA PARA UN TEXTO PEQUEÑO
        val s2 = "hola mundo FASFS FL;SKHFO"
        val r2 = aes.generateHmac(s2, hashEncrypt)
        println(">>: r2: { length:  ${r2.length}, r2: $r2 }")

        if (r1.length!=r2.length) assertTrue(false)

        // PROBANDO LA LONGITUD DE LA RESPUESTA PARA UN TEXTO GRANDE
        val s3 = "RabtLEt2b4CDYtprp1zBtPiMyulxfVx40cR5HYtyHyCVSG0wV2udbtxfHW2Xw5d08DLjERtacpPyP1EbfS3AUvvzNWyZmUu+eoJ85xkAF8wDgFdmR9+UYxc1xd0Yt9ghzf1S6sR1It4pqsMBmKGG8uXc/mXfsSl97g6v7kLlHDA="
        val r3 = aes.generateHmac(s3, hashEncrypt)
        println(">>: r3: { length:  ${r3.length}, r3: $r3 }")

        assertEquals(r2.length, r3.length)

    }

    /**
     * esta prueba falla, en caso de que la longitud del resultado de la función generateHmac sea
     * diferente a 45.
     */
    @Test
    fun returnTrueIfgHmacResultLengthIs45() {
        val data = "pudin de limon" // probar distintos valores, siempre debe dar 44 al final
        val r = aes.generateHmac(data, hashEncrypt)
        println(">>: r: ${r.length}")
        assertEquals(r.length, 45)
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

        val originalMessage = "yopmail@yopmail.com"

        val encrypt = aes.code(originalMessage, hashEncrypt, symmetricAccess)
//        println(">>: encrypt: $encrypt")

        val key = aes.decode(symmetricAccess, hashEncrypt)
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

        val encrypt = "A45pFeUyNBMvdcuKFDi8xA==1imeT0NhPqYWgzn95VfviB7wpMZRE+bswQU5Czt6eoo=+vmMTXoo4udr+dtsjoNKa7Q7ekw72EvWXH9usJDFXpY=" // valor encriptado por el backend
        val expected = "yolanda@yopmail.com" // valor esperado por el backend

        val key = aes.decode(symmetricAccess, hashEncrypt)

        val message = aes.decode(encrypt, key)

        assertEquals(message, expected)

    }

}