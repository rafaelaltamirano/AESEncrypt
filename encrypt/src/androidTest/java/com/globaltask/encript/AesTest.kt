package com.globaltask.encript

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.globaltask.encript.aes.Aes

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class AesTest {

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

//        val encrypt = "r91RBh5PjB/Dit4AlDEO6tpGoReeJMMaqZdXsdy6e30iNc1dKP4fxMeCFwLqfS/yWyjwJ+nBHrls7+95WQlnpA1NIlqf600eVOjIZHgMVFQ="
        val encrypt = "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"
        val expected = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDsqZai3tvPWRy8ikE3pcyAM/Nw4E40u/0S+RakWV/q0sCaBdQrNTnu2jz9h3cy14uLvVhMdgq6q/MQKmvmHP4UAPBs+Vg4Vg/p5/ISI9n9BtC71jQsl0JyuPq+yTb7dJT95oOuJz434a5aQb1zbNsAXWu/U0XJC/gAWmuEg7DJn5MF6VTgb4I1h8wlDV+3GlNDMOBX0wFxFcNReF5YWy00ax40xKNbDso8ltxQRYnx7PfeKUDB/Vpt7RtFlqnxIlcEhD4oojj//J+T9BgCYE3OyCfMFi4eQB8x87iip0Rh+/ES0AUm3Se2YydwVcoME6R8v0qOVujOClJmfgInCf2PAgMBAAECggEBAJm3AP9irvS7VZ3kUr3ZM72lgJ41Ira/z32uShWPc2xrXOvtk0RJOwq3t1uYzEQ6mgm2fw6SsR9UJfi/BPweoqzNe1vcjH9y7r0niSRdIu5kqdkHJTY9PMyU91BKEys6KrfLLIZGOPRE4mD/SBUbhBd1llFbvfz6iCd6k1Er0/zwJ+YGC2KOpW1v8KdhPbVjP2c800N8/U96M3j1sa6Thu73BQrgdOjtxUTv6aLxXVemn65eqhLOUTYLSla+fOeWoecUPS4JxbPdjfwO6KHtAphMheNis+t7Wop22k02gEfufWslYx+zDAIRf76mbFMIuraCMLTvSmLE8Y0oYcakA+ECgYEA99kL4AAMEV+l6UggiCWUgiF0L3RRFbiRuAuZZDVFn1HwXtatxEt4EbjztAeniSE3aTUOjX1ferjQmGwQjPWwA3IJ4j9EX4ykXjA6ZwFiFlrZ5GQ7XStasBeO0HM2oMLC5U4VxTnHDon8KUg/OxavwLvc6U0sSnxRtdqb0kdYfv8CgYEA9HJblKnExzoOYKgrqg5twxFp39/kO9AkVKxlwpVqf+YpDXqG2qyhJ2i0kIg0J3rAKHU2h9Z3kHPA8eeobnXH+DVfpipWLt1AJusEncWeVN2e8uuTr6wGaKzYjXHoj/QTkHbxaLBWX0phGaPQaq9hXYMvzzoIqUOxw/3wvEJ1EXECgYAbLBeKMlcgXH0jCz5NztjuP16uiTEOkZKgO91QSCre4avZqe2ZFLEQOFe3iBNNDHA3v5Jd3r3mBXcRDt/tpE3swsbkoA0N8KxgiycL/fHUA5fZ20dK2qLxpVOJ9OerTk7xttLaMZBqPqR/niUYhE82cSIyDbzqWaDXsCTfM+U23wKBgFTldqr9/yqWHjIxleCc3EAYRyYKkzC2zDdgHINk8zTyUaWtvTIrLFkMg1GDDGH9vskOVF7+/E199i/NnfCnFUk9+Dc0kvP5wXMCwnqtDJ06zx5c9NDZNOybwyX0vqloQnc06AjM3WKA6ZJHE3ZJ7M3WZv9Yj3OB4DZKdpZbml7xAoGAXmJnAMyrnl7uVFF2Gxyg/suW7S668A0EDcQ/KKgSzEbrl2rmZ+16DYW8NWgqrpiSe0KtuBUcxH1q1ZnCT8ivxXFBleF8S6YUAKWbd1QGBciV+fosQzt3w0gSVG9FgmhFlWz/ci5BiVWuHft66GTHG/3pMZCJYxSVdl7jLm8AHAU="

        val message = aes.decode(encrypt, true)

        assertEquals(message, expected)

    }

}