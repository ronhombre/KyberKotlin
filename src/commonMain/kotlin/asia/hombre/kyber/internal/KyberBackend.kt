package asia.hombre.kyber.internal

import asia.hombre.kyber.*

internal expect object KyberBackend {
    fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray): KyberKEMKeyPair
    fun generate(parameter: KyberParameter, pkeSeed: ByteArray): KyberPKEKeyPair
    fun encrypt(key: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText
    fun decrypt(key: KyberDecryptionKey, cipherText: KyberCipherText): ByteArray
    fun encapsulate(key: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult
    fun decapsulate(key: KyberDecapsulationKey, cipherText: KyberCipherText): ByteArray
}
