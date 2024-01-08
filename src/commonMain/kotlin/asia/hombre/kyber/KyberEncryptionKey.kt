package asia.hombre.kyber

class KyberEncryptionKey(
    override val parameter: KyberParameter,
    override val keyBytes: ByteArray,
    val nttSeed: ByteArray) : KyberPKEKey {
        val fullBytes: ByteArray
            get() {
                val output = ByteArray(keyBytes.size + nttSeed.size)

                keyBytes.copyInto(output)
                nttSeed.copyInto(output, keyBytes.size)

                return output
            }
    }