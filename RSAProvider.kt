package com.app

import android.util.Base64
import org.spongycastle.util.io.pem.PemReader
import java.io.StringReader
import java.security.KeyFactory
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class RSAProvider {

    private val transformation = "RSA/ECB/PKCS1Padding"
    private val publicKeyString =
        "-----BEGIN PUBLIC KEY-----\ny" +
                "o" +
                "u" +
                "y" +
                "k" +
                "e" +
                "y\n-----END PUBLIC KEY-----"


    fun encrypt(data: ByteArray): String {

        val reader = PemReader(StringReader(publicKeyString))
        val pemObject = reader.readPemObject()
        val keyBytes: ByteArray = pemObject.content
        val keySpec: EncodedKeySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val key = keyFactory.generatePublic(keySpec)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val cipherData: ByteArray = cipher.doFinal(data)

        return Base64.encodeToString(cipherData, Base64.NO_WRAP)

    }

}