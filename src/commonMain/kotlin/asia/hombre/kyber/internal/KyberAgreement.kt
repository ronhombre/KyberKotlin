package asia.hombre.kyber.internal

import asia.hombre.kyber.*
import asia.hombre.kyber.exceptions.MismatchingKyberVariantException

internal object KyberAgreement {
    fun toCipherText(key: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        require(plainText.size == KyberConstants.N_BYTES && randomness.size == KyberConstants.N_BYTES)
        return KyberBackend.encrypt(key, plainText, randomness)
    }

    fun fromCipherText(key: KyberDecryptionKey, cipherText: KyberCipherText): ByteArray {
        if (key.parameter != cipherText.parameter) throw MismatchingKyberVariantException()
        return KyberBackend.decrypt(key, cipherText)
    }

    fun encapsulate(key: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult {
        require(plainText.size == KyberConstants.N_BYTES)
        return KyberBackend.encapsulate(key, plainText)
    }

    fun decapsulate(key: KyberDecapsulationKey, cipherText: KyberCipherText): ByteArray {
        if (key.parameter != cipherText.parameter) throw MismatchingKyberVariantException()
        return KyberBackend.decapsulate(key, cipherText)
    }
}
