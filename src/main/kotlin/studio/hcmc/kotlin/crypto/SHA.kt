package studio.hcmc.kotlin.crypto

import java.math.BigInteger
import java.security.MessageDigest

val String.sha512: String get() {
    return MessageDigest.getInstance("SHA-512")
        .apply { reset() }
        .apply { update(toByteArray()) }
        .digest()
        .run { BigInteger(1, this) }
        .let { String.format("%0128x", it) }
}