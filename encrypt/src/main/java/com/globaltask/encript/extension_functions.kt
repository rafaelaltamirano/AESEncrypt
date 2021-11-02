package com.globaltask.encript

import android.util.Base64

const val base64flag = Base64.DEFAULT

fun ByteArray.toBase64(): String {
    return Base64.encodeToString(this, base64flag).replace("\n", "")
}

/**
 * Función de extensión que facilita la decodificacion de un texto en Base64 a ByteArray
 */
fun String.base64ToByteArray(): ByteArray {
    return Base64.decode(this, base64flag)
}