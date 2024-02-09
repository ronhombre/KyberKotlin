/*
 * Copyright 2024 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package asia.hombre.kyber

import asia.hombre.kyber.exceptions.DecapsulationException
import asia.hombre.kyber.exceptions.EncapsulationException
import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import org.kotlincrypto.hash.sha3.SHAKE256

/**
 * A Key Agreement for encapsulating and decapsulating.
 * @param kemKeyPair
 * @constructor Creates a Key Agreement for encapsulating and decapsulating.
 * @author Ron Lauren Hombre
 */
class KyberAgreement(kemKeyPair: KyberKEMKeyPair) {
    val parameter: KyberParameter
    val keypair: KyberKEMKeyPair = kemKeyPair

    init {
        this.parameter = kemKeyPair.encapsulationKey.key.parameter
    }

    /**
     * Internal function to generate a Cipher Text. Synonymous to K.PKE.Encrypt() in FIPS 203.
     * @param encryptionKey Encryption Key of the second party.
     * @param plainText Plain Text
     * @param randomness Random 32 Bytes
     * @return KyberCipherText The Cipher Text to send to the second party.
     */
    internal fun toCipherText(encryptionKey: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        val decodedKey = KyberMath.byteDecode(encryptionKey.keyBytes, 12)
        val nttKeyVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

        val nttSeed = encryptionKey.nttSeed

        val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
        val randomnessVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
        val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

        for((n, i) in (0..<parameter.K).withIndex()) {
            decodedKey.copyInto(
                nttKeyVector[i],
                0,
                KyberConstants.N * i,
                KyberConstants.N * (i + 1)
            )

            nttKeyVector[i] = KyberMath.vectorToMontVector(nttKeyVector[i])

            randomnessVector[i] = KyberMath.samplePolyCBD(
                parameter.ETA1,
                KyberMath.prf(parameter.ETA1, randomness, n.toByte())
            )
            randomnessVector[i] = KyberMath.NTT(randomnessVector[i])

            noiseVector[i] = KyberMath.samplePolyCBD(
                parameter.ETA2,
                KyberMath.prf(parameter.ETA2, randomness, (n + parameter.K).toByte())
            )

            for(j in 0..<parameter.K) {
                matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))
            }
        }

        val noiseTerm = KyberMath.samplePolyCBD(
            parameter.ETA2,
            KyberMath.prf(parameter.ETA2, randomness, ((parameter.K * 2) + 1).toByte())
        )

        val muse = KyberMath.singleDecompress(KyberMath.singleByteDecode(plainText))

        val coefficients = KyberMath.nttMatrixToVectorDot(matrix, randomnessVector)

        var constantTerm = ShortArray(KyberConstants.N)
        for(i in 0..<parameter.K) {
            coefficients[i] = KyberMath.invNTT(coefficients[i])
            coefficients[i] = KyberMath.vectorToVectorAdd(coefficients[i], noiseVector[i])

            constantTerm = KyberMath.vectorToVectorAdd(constantTerm, KyberMath.multiplyNTTs(nttKeyVector[i], randomnessVector[i]))
        }

        constantTerm = KyberMath.invNTT(constantTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, noiseTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, muse)

        val encodedCoefficients = ByteArray(KyberConstants.N_BYTES * (parameter.DU * parameter.K))
        val encodedTerms = ByteArray(KyberConstants.N_BYTES * parameter.DV)

        for(i in 0..<parameter.K) {
            KyberMath.byteEncode(KyberMath.compress(KyberMath.montVectorToVector(coefficients[i]), parameter.DU), parameter.DU)
                .copyInto(encodedCoefficients, i * KyberConstants.N_BYTES * parameter.DU)
        }

        KyberMath.byteEncode(KyberMath.compress(KyberMath.montVectorToVector(constantTerm), parameter.DV), parameter.DV).copyInto(encodedTerms)

        return KyberCipherText(parameter, encodedCoefficients, encodedTerms)
    }

    /**
     * Internal function to decrypt a Cipher Text. Synonymous to K.PKE.Decrypt() in FIPS 203.
     * @param cipherText Cipher Text from the second party.
     * @return ByteArray The original Plain Text.
     */
    internal fun fromCipherText(cipherText: KyberCipherText): ByteArray {
        val coefficients = Array(cipherText.parameter.K) { ShortArray(KyberConstants.N) }

        for (i in 0..<parameter.K) {
            coefficients[i] = KyberMath.decompress(
                KyberMath.byteDecode(
                    cipherText.encodedCoefficients.copyOfRange(
                        i * KyberConstants.N_BYTES * parameter.DU,
                        (i + 1) * KyberConstants.N_BYTES * parameter.DU),
                    parameter.DU
                ),
                parameter.DU
            )
            coefficients[i] = KyberMath.vectorToMontVector(coefficients[i])
        }

        var constantTerms = KyberMath.decompress(KyberMath.byteDecode(cipherText.encodedTerms, parameter.DV), parameter.DV)
        constantTerms = KyberMath.vectorToMontVector(constantTerms)

        val secretVector = KyberMath.byteDecode(keypair.decapsulationKey.key.keyBytes, 12)

        for (i in 0..<parameter.K) {
            val subtraction = KyberMath.invNTT(
                KyberMath.multiplyNTTs(
                    KyberMath.vectorToMontVector(secretVector.copyOfRange(
                        i * KyberConstants.N,
                        (i + 1) * KyberConstants.N)),
                    KyberMath.NTT(coefficients[i])
                )
            )
            for (j in 0..<KyberConstants.N)
                constantTerms[j] = KyberMath.barrettReduce((constantTerms[j] - subtraction[j]).toShort())
        }

        constantTerms = KyberMath.montVectorToVector(constantTerms)

        return KyberMath.byteEncode(KyberMath.compress(constantTerms, 1), 1)
    }

    /**
     * Encapsulation function for non-testing use case
     * @param kyberEncapsulationKey Encapsulation Key of the second party.
     * @return KyberEncapsulationResult Contains the Cipher Text and the generated Secret Key.
     */
    internal fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey): KyberEncapsulationResult {
        return encapsulate(kyberEncapsulationKey, SecureRandom().nextBytesOf(KyberConstants.N_BYTES))
    }

    /**
     * Internal Encapsulation function that could be used for testing purposes. Synonymous to ML-KEM.Encaps() in FIPS 203.
     * @param kyberEncapsulationKey Encapsulation Key of the second party.
     * @param plainText The Plain Text to use.
     * @return KyberEncapsulationResult Contains the Cipher Text and the generated Secret Key.
     */
    internal fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult {
        if(kyberEncapsulationKey.key.fullBytes.size != parameter.ENCAPSULATION_KEY_LENGTH)
            throw EncapsulationException("ML-KEM variant mismatch!")
        if(!KyberMath.byteEncode(KyberMath.byteDecode(kyberEncapsulationKey.key.keyBytes, 12), 12)
            .contentEquals(kyberEncapsulationKey.key.keyBytes))
            throw EncapsulationException("Modulus not of " + KyberConstants.Q)

        val sha3256 = SHA3_256()

        sha3256.update(kyberEncapsulationKey.key.fullBytes)

        val sha3512 = SHA3_512()

        sha3512.update(plainText)
        sha3512.update(sha3256.digest())

        val sharedKeyAndRandomness = sha3512.digest()

        val cipherText = toCipherText(kyberEncapsulationKey.key, plainText, sharedKeyAndRandomness.copyOfRange(32, 64))

        return KyberEncapsulationResult(sharedKeyAndRandomness.copyOfRange(0, 32), cipherText)
    }

    /**
     * Decapsulation function to recover the Secret Keys from the Cipher Text. Synonymous to ML-KEM.Decaps() in FIPS 203.
     * @param cipherText The Cipher Text from the second party.
     * @return ByteArray The Secret Key
     */
    internal fun decapsulate(cipherText: KyberCipherText): ByteArray {
        if(cipherText.fullBytes.size != parameter.CIPHERTEXT_LENGTH)
            throw DecapsulationException("ML-KEM cipher text variant mismatch!")
        if(keypair.decapsulationKey.fullBytes.size != parameter.DECAPSULATION_KEY_LENGTH)
            throw DecapsulationException("ML-KEM Decapsulation Key is non-standard!")

        val recoveredPlainText = fromCipherText(cipherText)

        val sha3512 = SHA3_512()

        sha3512.update(recoveredPlainText)
        sha3512.update(keypair.decapsulationKey.hash)

        val decapsHash = sha3512.digest()

        val shake256 = SHAKE256(KyberConstants.SECRET_KEY_LENGTH)

        shake256.update(keypair.decapsulationKey.randomSeed)
        shake256.update(cipherText.fullBytes)

        val secretKeyRejection = shake256.digest()

        var secretKeyCandidate = decapsHash.copyOfRange(0, KyberConstants.SECRET_KEY_LENGTH)
        val regeneratedCipherText = toCipherText(
            keypair.decapsulationKey.encryptionKey,
            recoveredPlainText,
            decapsHash.copyOfRange(32, 64)
        )

        if(!cipherText.fullBytes.contentEquals(regeneratedCipherText.fullBytes))
            secretKeyCandidate = secretKeyRejection //Implicit Rejection

        return secretKeyCandidate
    }
}