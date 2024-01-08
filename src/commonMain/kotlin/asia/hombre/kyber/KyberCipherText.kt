package asia.hombre.kyber

class KyberCipherText(val parameter: KyberParameter, val encodedCoefficients: ByteArray, val encodedTerms: ByteArray) {
    val fullBytes: ByteArray
        get() {
            val output = ByteArray(32 * ((parameter.DU * parameter.K) + parameter.DV))

            encodedCoefficients.copyInto(output, 0)
            encodedTerms.copyInto(output, encodedCoefficients.size)

            return output
        }
}