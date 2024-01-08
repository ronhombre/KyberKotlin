package asia.hombre.kyber

class KyberDecapsulationKey(
    override val key: KyberDecryptionKey,
    val encryptionKey: KyberEncryptionKey,
    val hash: ByteArray,
    val randomSeed: ByteArray) : KyberKEMKey {
        val fullBytes: ByteArray
            get() {
                val output = ByteArray(key.keyBytes.size + encryptionKey.fullBytes.size + hash.size + randomSeed.size)

                key.keyBytes.copyInto(output)
                encryptionKey.fullBytes.copyInto(output, key.keyBytes.size)
                hash.copyInto(output, key.keyBytes.size + encryptionKey.fullBytes.size)
                randomSeed.copyInto(output, output.size - randomSeed.size)

                return output
            }
    }