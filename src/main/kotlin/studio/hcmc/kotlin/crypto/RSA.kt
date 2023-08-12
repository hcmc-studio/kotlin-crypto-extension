package studio.hcmc.kotlin.crypto

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

object RSA {
    data class KeyPair(
        val publicKey: String,
        val privateKey: String
    )
}

private fun ByteArray.toKeyString(): String {
    return Base64.getEncoder().encodeToString(this)
}

private fun String.toKeyArray(): ByteArray {
    return Base64.getDecoder().decode(this)
}

private fun String.toPublicKey(): PublicKey {
    return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(this.toKeyArray()))
}

private fun String.toPrivateKey(): PrivateKey {
    return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(this.toKeyArray()))
}

fun RSA.createKeyPair(keySize: Int): RSA.KeyPair {
    val keyPair = KeyPairGenerator.getInstance("RSA").run {
        initialize(keySize)
        generateKeyPair()
    }
    return RSA.KeyPair(
        publicKey = keyPair.public.encoded.toKeyString(),
        privateKey = keyPair.private.encoded.toString()
    )
}

fun RSA.encrypt(plainString: String, publicKey: String, keySize: Int): String {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey.toPublicKey())

    val plainBytes = plainString.toByteArray()
    val blockSize = keySize / 8 - 11
    val blocks = plainBytes.size / blockSize
    return ByteArrayOutputStream().use { stream ->
        for (i in 0..<blocks) {
            stream.write(cipher.doFinal(plainBytes, i * blockSize, blockSize))
        }

        val lastPosition = blocks * blockSize
        if (plainBytes.size != lastPosition) {
            stream.write(cipher.doFinal(plainBytes, lastPosition, plainBytes.size - lastPosition))
        }

        Base64.getEncoder().encodeToString(stream.toByteArray())
    }
}

fun RSA.decrypt(encryptedString: String, privateKey: String, keySize: Int): String {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING")
    cipher.init(Cipher.DECRYPT_MODE, privateKey.toPrivateKey())

    val encryptedBytes = Base64.getDecoder().decode(encryptedString.toByteArray())
    val blockSize = keySize / 8
    val blocks = encryptedBytes.size / blockSize
    return ByteArrayOutputStream().use { stream ->
        for (i in 0..<blocks) {
            stream.write(cipher.doFinal(encryptedBytes, i * blockSize, blockSize))
        }

        val lastPosition = blocks * blockSize
        if (encryptedBytes.size != lastPosition) {
            stream.write(cipher.doFinal(encryptedBytes, lastPosition, encryptedBytes.size - lastPosition))
        }

        String(stream.toByteArray())
    }
}