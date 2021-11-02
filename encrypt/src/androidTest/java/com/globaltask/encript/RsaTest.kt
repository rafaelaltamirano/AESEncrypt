package com.globaltask.encript

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.globaltask.encript.aes.Aes
import com.globaltask.encript.rsa.Rsa
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RsaTest {

    companion object  {

        // CONSTANTES
        private const val SECURITY_ENCRYPTION_SYMMETRIC_KEY = "DAgawS2KsZBRyElqMUOJhLiQqnVTvli4B59qm1XeSQM="
        private const val SECURITY_ENCRYPTION_HMACKEY = "C73e7IZeeEhqQjXjJFf1ug=="

        // TEMPORALES ENCRIPTADAS
        private const val publicTemporaryEncryptedKey = "8M631sjNXfRwP4bVCGHM0+nRyWp73bJgAc3V2kYhD8jJS9ZKv+Xwz8E8QN6vH9COCWDMipJcgVUfHOr77BXtKuWZfn055ckxZ2a5gEpISFKCX/3+HlNu+OesjVWK8JtxcdrKweShI+BYXOBvSncgxA2A8fjMQBl8xhSYsQEXFhINVx2junV+Ba+ZLufmJA12c63iqWXA8C2pru3MybjA6I0+/dt6iEXIIKpSnKtN/iFPJ54ai4Zk99VszPYDz4CwlBw607GRxsDbETCOr2IFnZVHQIuPzOjE3Z3FTOXZOwujJ103x40uPUC7BlnzbwUJEZCFgEPo528KjOa8F7jExkRxi19Vi5iCzGKy+W9S+zde5b/oCJwPDYOXZMSchOcEDQGKmC4At3NiKzBvy1Ecw1rZeGPsxDpYSe14reEm5+Cwtw/BIcYOFOwnqIJN1a92Li8FDQ7q07CB2SocAdToa6GjSGEeIzrAow7efF9Py6ugquPKeWujSzkolOkVKrHPZ3tc6/BW2KiH8GcHnODakFr3Ytwp0EnRK45DksKPIZW8EJRDpUe9q0baJ6hTT91aTIkNQZHxqh09TE/yKbpojQ=="
        private const val privateTemporaryEncryptedKey = "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"

        // CREANDO LA INSTANCIA DEL AES
        private val aes = Aes.getInstance(SECURITY_ENCRYPTION_SYMMETRIC_KEY, SECURITY_ENCRYPTION_HMACKEY)
        private val rsa = Rsa.getInstance(aes)

    }

    @Test
    fun returnTrueIfCodeAndDecodeSuccess() {

        rsa.setTemporaryEncryptedKeys(publicTemporaryEncryptedKey, privateTemporaryEncryptedKey)

        val originalMessage = "yolanda@yopmail.com"

        val encrypt = rsa.code(originalMessage)
        println(">>: encrypt: $encrypt")

        val message = rsa.decode(encrypt)

        Assert.assertEquals(message, originalMessage)

    }

    @Test
    fun returnTrueIfRemoteMessageIfDecode() {

        rsa.setTemporaryEncryptedKeys(publicTemporaryEncryptedKey, privateTemporaryEncryptedKey)

        val encrypt = "SU1b3N25iXoTNU/rQrpbC9QRtggg4cNY9rYliELO5Zv4RCXg+fs5xfnR4ZtZMNId6kySZsU2JH4F\n" +
                "yMTgNI7hhYgIceuZqfrkd5+V/s9S4ACLFBUIrMh8a92TtKIoFt0kl4h8pZfFBRVkuq7BOuLSNMHF\n" +
                "so8+8e0zRWeFmjy/eeq3OzSjqYVz3bFQ1oJcyS2OXZ/XaaMRrsx9i5twRc8igK3BQOBdl9fRmdgw\n" +
                "fzf6r3dA22ii1U6m9JrBiJnc1s5A0z9Htiu9plY77sJ2NFbldkJZQ9YUUZgqYJG6SabU5uAHAKMK\n" +
                "ioj4DSZAmglQOcCqZVmFgcEfcbHJ0MAyqUfhsQ=="
        val expected = "yolanda@yopmail.com"

        val message = rsa.decode(encrypt)

        Assert.assertEquals(message, expected)

    }


}