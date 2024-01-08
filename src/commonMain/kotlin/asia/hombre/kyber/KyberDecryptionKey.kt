package asia.hombre.kyber

class KyberDecryptionKey(
    override val parameter: KyberParameter,
    override val keyBytes: ByteArray) : KyberPKEKey