package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import org.kotlincrypto.hash.sha3.SHAKE256

class KeyAgreement {
    val parameter: KyberParameter
    val keypair: KyberKEMKeyPair
    constructor(kemKeyPair: KyberKEMKeyPair) {
        this.parameter = kemKeyPair.encapsulationKey.key.parameter
        this.keypair = kemKeyPair
    }

    fun toCipherText(encryptionKey: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        val decodedKey = KyberMath.byteDecode(encryptionKey.keyBytes, 12)
        val nttKeyVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

        for(i in 0..<parameter.K)
            decodedKey.copyInto(nttKeyVector[i], 0, KyberConstants.N * i, KyberConstants.N * (i + 1))

        val nttSeed = encryptionKey.nttSeed

        val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
        val randomnessVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
        val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
        var coefficients = Array(parameter.K) { ShortArray(KyberConstants.N) }

        var nonce = 0
        for((n, i) in (0..<parameter.K).withIndex()) {
            nonce = n

            randomnessVector[i] = KyberMath.samplePolyCBD(parameter.ETA1, KyberMath.prf(parameter.ETA1, randomness, nonce.toByte()))
            randomnessVector[i] = KyberMath.NTT(randomnessVector[i])

            noiseVector[i] = KyberMath.samplePolyCBD(parameter.ETA2, KyberMath.prf(parameter.ETA2, randomness, (nonce + parameter.K).toByte()))

            for(j in 0..<parameter.K) {
                matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))
            }
        }

        val noiseTerm = KyberMath.samplePolyCBD(parameter.ETA2, KyberMath.prf(parameter.ETA2, randomness, (++nonce).toByte()))

        for(i in 0..<parameter.K) {
            val temp = Array(parameter.K) { ShortArray(KyberConstants.N) }
            for (j in 0..<parameter.K)
                temp[j] = KyberMath.multiplyNTTs(matrix[j][i], randomnessVector[i])
            coefficients = KyberMath.vectorAddition(coefficients, temp)
        }

        coefficients = KyberMath.vectorAddition(coefficients, noiseVector)

        val muse = KyberMath.decompress(KyberMath.byteDecode(plainText, 1), 1)

        //START << THIS PART IS BASED FROM FiloSottile/mlkem768

        var constantTerm = ShortArray(KyberConstants.N)
        for(i in 0..<parameter.K) {
            constantTerm = KyberMath.vectorToVectorAdd(constantTerm, KyberMath.multiplyNTTs(nttKeyVector[i], randomnessVector[i]))
        }

        constantTerm = KyberMath.invNTT(constantTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, noiseTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, muse)

        //END << THIS PART IS BASED FROM FiloSottile/mlkem768

        val encodedCoefficients = ByteArray(32 * (parameter.DU * parameter.K))
        val encodedTerms = ByteArray(32 * parameter.DV)

        for(i in 0..<parameter.K) {
            KyberMath.byteEncode(KyberMath.compress(coefficients[i], parameter.DU), parameter.DU).copyInto(encodedCoefficients, i * 32 * parameter.DU)
        }

        KyberMath.byteEncode(KyberMath.compress(constantTerm, parameter.DV), parameter.DV).copyInto(encodedTerms)

        return KyberCipherText(parameter, encodedCoefficients, encodedTerms)
    }

    fun fromCipherText(cipherText: KyberCipherText): ByteArray {
        val coefficients = Array(cipherText.parameter.K) { ShortArray(KyberConstants.N) }

        for (i in 0..<parameter.K) {
            coefficients[i] = KyberMath.decompress(
                KyberMath.byteDecode(
                    cipherText.encodedCoefficients.copyOfRange(
                        i * 32 * parameter.DU,
                        (i + 1) * 32 * parameter.DU
                    ), parameter.DU
                ), parameter.DU
            )
        }

        val constantTerms =
            KyberMath.decompress(KyberMath.byteDecode(cipherText.encodedTerms, parameter.DV), parameter.DV)
        val secretVector = KyberMath.byteDecode(keypair.decapsulationKey.key.keyBytes, 12)

        val trueConstantTerm = constantTerms

        for (i in 0..<parameter.K) {
            val subtraction = KyberMath.invNTT(KyberMath.multiplyNTTs(secretVector, KyberMath.NTT(coefficients[i])))
            for (j in 0..<KyberConstants.N)
                trueConstantTerm[j] = (trueConstantTerm[j] - subtraction[j]).toShort()
        }

        return KyberMath.byteEncode(KyberMath.compress(trueConstantTerm, 1), 1)
    }

    fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey): KyberEncapsulationResult {
        val plainText = SecureRandom.generateSecureBytes(32)

        val sha3512 = SHA3_512()
        sha3512.update(plainText)

        val sha3256 = SHA3_256()

        sha3512.update(sha3256.digest(kyberEncapsulationKey.key.fullBytes))

        val sharedKeyAndRandomness = sha3512.digest()

        val cipherText = toCipherText(kyberEncapsulationKey.key, plainText, sharedKeyAndRandomness.copyOfRange(32, 64))

        return KyberEncapsulationResult(sharedKeyAndRandomness.copyOfRange(0, 32), cipherText)
    }

    fun decapsulate(cipherText: KyberCipherText): ByteArray {
        val decryptionKey = keypair.decapsulationKey.key
        val encryptionKey = keypair.decapsulationKey.encryptionKey
        val encryptionHash = keypair.decapsulationKey.hash
        val rejections = keypair.decapsulationKey.randomSeed

        val recoveredPlainText = fromCipherText(cipherText)

        val sha3512 = SHA3_512()

        sha3512.update(recoveredPlainText)
        sha3512.update(encryptionHash)

        val KprimeAndRandomprime = sha3512.digest()

        val shake256 = SHAKE256(32)

        shake256.update(rejections)
        shake256.update(cipherText.fullBytes)

        val Kbar = shake256.digest()

        var Kprime = KprimeAndRandomprime.copyOfRange(0, 32)
        val cprime = toCipherText(encryptionKey, recoveredPlainText, KprimeAndRandomprime.copyOfRange(32, 64))

        if(!cipherText.fullBytes.contentEquals(cprime.fullBytes))
            Kprime = Kbar

        return Kprime
    }
}