package com.app

import android.util.Base64
import android.util.Base64.NO_WRAP
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class AESProvider {
    
    private var key: SecretKey? = null
    private val KEY_SIZE = 128
    private var encryptionCipher: Cipher? = null

    fun getKey(): SecretKey? {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(KEY_SIZE)
        key = generator.generateKey()
        return key
    }

    @Throws(Exception::class)
    fun encrypt(message: String): String {

        val messageInBytes = message.toByteArray()
        encryptionCipher = Cipher.getInstance("AES")
        encryptionCipher!!.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes: ByteArray = encryptionCipher!!.doFinal(messageInBytes)
        return Base64.encodeToString(encryptedBytes, NO_WRAP)
    }
}