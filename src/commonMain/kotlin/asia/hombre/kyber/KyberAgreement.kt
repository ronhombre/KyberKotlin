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

import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import org.kotlincrypto.hash.sha3.SHAKE256
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.js.JsName
import kotlin.jvm.JvmSynthetic

/**
 * An agreement class for Encapsulating ML-KEM Keys and Decapsulating Cipher Texts.
 *
 * This class contains K-PKE.Encrypt(), K-PKE.Decrypt(), ML-KEM.Encaps(), and ML-KEM.Decaps() all according to NIST FIPS 203.
 *
 * @param kemKeyPair [KyberKEMKeyPair]
 * @constructor Stores the key pair for encapsulating and decapsulating.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberAgreement(kemKeyPair: KyberKEMKeyPair) {
    /**
     * The [KyberParameter] of this agreement.
     */
    val parameter: KyberParameter = kemKeyPair.encapsulationKey.key.parameter

    private val keypair: KyberKEMKeyPair = kemKeyPair

    internal companion object {
        /**
         * Private Encryption function.
         *
         * This method is the K-PKE.Encrypt() specified in NIST FIPS 203.
         *
         * @param encryptionKey [KyberEncryptionKey] of the second party.
         * @param plainText [ByteArray] Plain Text to encrypt.
         * @param randomness [ByteArray] Random bytes as random source.
         * @return [KyberCipherText] - The Cipher Text to send to the second party.
         */
        private fun toCipherText(encryptionKey: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
            val parameter = encryptionKey.parameter
            val decodedKey = KyberMath.byteDecode(encryptionKey.keyBytes, 12)
            val nttKeyVector = Array(parameter.K) { IntArray(KyberConstants.N) }

            val nttSeed = encryptionKey.nttSeed

            val matrix = Array(parameter.K) { Array(parameter.K) { IntArray(KyberConstants.N) } }
            val randomnessVector = Array(parameter.K) { IntArray(KyberConstants.N) }
            val noiseVector = Array(parameter.K) { IntArray(KyberConstants.N) }

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

            var constantTerm = IntArray(KyberConstants.N)
            for(i in 0..<parameter.K) {
                coefficients[i] = KyberMath.invNTT(coefficients[i])
                coefficients[i] = KyberMath.vectorToVectorAdd(coefficients[i], noiseVector[i])

                constantTerm = KyberMath.vectorToVectorAdd(constantTerm, KyberMath.multiplyNTTs(nttKeyVector[i], randomnessVector[i]))

                //Security Features
                for(j in 0..<parameter.K) matrix[i][j].fill(0, 0, matrix[i][j].size)
                noiseVector[i].fill(0, 0, noiseVector[i].size)
                nttKeyVector[i].fill(0, 0, nttKeyVector[i].size)
                randomnessVector[i].fill(0, 0, randomnessVector[i].size)
            }

            constantTerm = KyberMath.invNTT(constantTerm)
            constantTerm = KyberMath.vectorToVectorAdd(constantTerm, noiseTerm)
            constantTerm = KyberMath.vectorToVectorAdd(constantTerm, muse)

            //Security Feature
            muse.fill(0, 0, muse.size)

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
         * Internal Decryption function for testing purposes.
         *
         * This method is the K-PKE.Decrypt() specified in NIST FIPS 203.
         *
         * @param decryptionKey [KyberDecryptionKey] from yourself.
         * @param kyberCipherText [KyberCipherText] from the second party.
         * @return [ByteArray] - The recovered Plain Text.
         */
        @JvmSynthetic
        internal fun fromCipherText(decryptionKey: KyberDecryptionKey, kyberCipherText: KyberCipherText): ByteArray {
            val parameter = kyberCipherText.parameter
            val coefficients = Array(kyberCipherText.parameter.K) { IntArray(KyberConstants.N) }

            for (i in 0..<parameter.K) {
                coefficients[i] = KyberMath.decompress(
                    KyberMath.byteDecode(
                        kyberCipherText.encodedCoefficients.copyOfRange(
                            i * KyberConstants.N_BYTES * parameter.DU,
                            (i + 1) * KyberConstants.N_BYTES * parameter.DU),
                        parameter.DU
                    ),
                    parameter.DU
                )
                coefficients[i] = KyberMath.vectorToMontVector(coefficients[i])
            }

            var constantTerms = KyberMath.decompress(KyberMath.byteDecode(kyberCipherText.encodedTerms, parameter.DV), parameter.DV)
            constantTerms = KyberMath.vectorToMontVector(constantTerms)

            val secretVector = KyberMath.byteDecode(decryptionKey.keyBytes, 12)

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
                    constantTerms[j] = KyberMath.barrettReduce(constantTerms[j] - subtraction[j])
            }

            constantTerms = KyberMath.montVectorToVector(constantTerms)

            return KyberMath.byteEncode(KyberMath.compress(constantTerms, 1), 1)
        }

        /**
         * Internal Encapsulation function for testing purposes.
         *
         * This method is the ML-KEM.Encaps() specified in NIST FIPS 203.
         *
         * @param kyberEncapsulationKey [KyberEncapsulationKey] of the second party.
         * @param plainText [ByteArray] The Plain Text to use.
         * @return [KyberEncapsulationResult] - Contains the Cipher Text and the generated Secret Key.
         */
        @JvmSynthetic
        internal fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult {
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
         * Decapsulates a KyberCipherText with a KyberDecapsulationKey and recovers the Secret Key.
         *
         * This method is the ML-KEM.Decaps() specified in NIST FIPS 203.
         *
         * @param decapsulationKey [KyberDecapsulationKey] from yourself.
         * @param kyberCipherText [KyberCipherText] received from sender.
         * @return [ByteArray] - The generated Secret Key, which is the same one generated by the sender.
         */
        fun decapsulate(decapsulationKey: KyberDecapsulationKey, kyberCipherText: KyberCipherText): ByteArray {
            val recoveredPlainText = fromCipherText(decapsulationKey.key, kyberCipherText)

            val sha3512 = SHA3_512()

            sha3512.update(recoveredPlainText)
            sha3512.update(decapsulationKey.hash)

            val decapsHash = sha3512.digest()

            val shake256 = SHAKE256(KyberConstants.SECRET_KEY_LENGTH)

            shake256.update(decapsulationKey.randomSeed)
            shake256.update(kyberCipherText.fullBytes)

            val secretKeyRejection = shake256.digest()

            var secretKeyCandidate = decapsHash.copyOfRange(0, KyberConstants.SECRET_KEY_LENGTH)

            val regeneratedCipherText = toCipherText(
                decapsulationKey.encryptionKey,
                recoveredPlainText,
                decapsHash.copyOfRange(32, 64)
            )

            //Security Feature
            decapsHash.fill(0, 0, decapsHash.size)

            if(!kyberCipherText.fullBytes.contentEquals(regeneratedCipherText.fullBytes))
                secretKeyCandidate = secretKeyRejection //Implicit Rejection

            return secretKeyCandidate
        }
    }

    /**
     * Encapsulates a [KyberEncapsulationKey] into a [KyberCipherText] and generates a Secret Key.
     *
     * This method is the ML-KEM.Encaps() specified in NIST FIPS 203.
     *
     * @param kyberEncapsulationKey [KyberEncapsulationKey] received from sender.
     * @return [KyberEncapsulationResult] - Contains the Cipher Text and the generated Secret Key.
     */
    @JsName("encapsulate")
    fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey): KyberEncapsulationResult {
        return encapsulate(kyberEncapsulationKey, SecureRandom().nextBytesOf(KyberConstants.N_BYTES))
    }

    /**
     * Decapsulates a [KyberCipherText] and recovers the Secret Key.
     *
     * This method is the ML-KEM.Decaps() specified in NIST FIPS 203.
     *
     * @param kyberCipherText [KyberCipherText] received from sender.
     * @return [ByteArray] - The generated Secret Key, which is the same one generated by the sender.
     */
    @JsName("decapsulate")
    fun decapsulate(kyberCipherText: KyberCipherText): ByteArray {
        return Companion.decapsulate(keypair.decapsulationKey, kyberCipherText)
    }
}