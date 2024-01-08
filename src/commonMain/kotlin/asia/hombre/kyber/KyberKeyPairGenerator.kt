package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512

class KyberKeyPairGenerator {
    constructor() //TODO

    fun generate(parameter: KyberParameter): KyberKEMKeyPair {
        val sha3256 = SHA3_256()

        val randomSeed = SecureRandom.generateSecureBytes(32)
        val pkeSeed = SecureRandom.generateSecureBytes(32)

        val pkeKeyPair = PKEGenerator.generate(parameter, pkeSeed)

        sha3256.update(pkeKeyPair.encryptionKey.keyBytes)
        sha3256.update(pkeKeyPair.encryptionKey.nttSeed)

        val hash = sha3256.digest().copyOfRange(0, 32)

        return KyberKEMKeyPair(KyberEncapsulationKey(pkeKeyPair.encryptionKey), KyberDecapsulationKey(pkeKeyPair.decryptionKey, pkeKeyPair.encryptionKey, hash, randomSeed))
    }

    internal class PKEGenerator {
        companion object {
            fun generate(parameter: KyberParameter, byteArray: ByteArray): KyberPKEKeyPair {
                val sha3512 = SHA3_512()

                val seeds = sha3512.digest(byteArray)

                val nttSeed = seeds.copyOfRange(0, KyberConstants.CPAPKE_BYTES)
                val cbdSeed = seeds.copyOfRange(KyberConstants.CPAPKE_BYTES, KyberConstants.CPAPKE_BYTES * 2)

                val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
                val secretVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
                val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

                for((nonce, i) in (0..<parameter.K).withIndex()) {
                    for(j in 0..<parameter.K) {
                        matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))
                    }

                    secretVector[i] = KyberMath.samplePolyCBD(parameter.ETA1, KyberMath.prf(parameter.ETA1, cbdSeed, nonce.toByte()))
                    secretVector[i] = KyberMath.NTT(secretVector[i])

                    noiseVector[i] = KyberMath.samplePolyCBD(parameter.ETA1, KyberMath.prf(parameter.ETA1, cbdSeed, (nonce + parameter.K).toByte()))
                    noiseVector[i] = KyberMath.NTT(noiseVector[i])
                }

                val systemVector = KyberMath.vectorAddition(KyberMath.nttMatrixMultiply(matrix, secretVector), noiseVector)

                val encodeSize = (1.5 * KyberConstants.N).toInt()
                val encryptionKeyBytes = ByteArray(encodeSize * parameter.K) //Excluded nttSeed
                val decryptionKeyBytes = ByteArray(encryptionKeyBytes.size)

                for(i in 0..<parameter.K) {
                    KyberMath.byteEncode(systemVector[i], 12).copyInto(encryptionKeyBytes, i * encodeSize)
                    KyberMath.byteEncode(secretVector[i], 12).copyInto(decryptionKeyBytes, i * encodeSize)
                }

                return KyberPKEKeyPair(KyberEncryptionKey(parameter, encryptionKeyBytes, nttSeed), KyberDecryptionKey(parameter, decryptionKeyBytes))
            }
        }
    }
}