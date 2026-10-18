package asia.hombre.kyber.internal

import asia.hombre.kyber.*

internal actual object KyberBackend {
    actual fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray) =
        CommonKyberKeyGenerator.generate(parameter, randomSeed, pkeSeed)

    actual fun generate(parameter: KyberParameter, pkeSeed: ByteArray) =
        CommonKyberKeyGenerator.PKEGenerator.generate(parameter, pkeSeed)

    actual fun encrypt(key: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray) =
        CommonKyberAgreement.toCipherText(key, plainText, randomness)

    actual fun decrypt(key: KyberDecryptionKey, cipherText: KyberCipherText) =
        CommonKyberAgreement.fromCipherText(key, cipherText)

    actual fun encapsulate(key: KyberEncapsulationKey, plainText: ByteArray) =
        CommonKyberAgreement.encapsulate(key, plainText)

    actual fun decapsulate(key: KyberDecapsulationKey, cipherText: KyberCipherText) =
        CommonKyberAgreement.decapsulate(key, cipherText)
}
