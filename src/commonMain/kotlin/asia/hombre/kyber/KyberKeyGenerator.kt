/*
 * Copyright 2025 Ron Lauren Hombre
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

import asia.hombre.keccak.api.SHA3_256
import asia.hombre.keccak.api.SHA3_512
import asia.hombre.kyber.exceptions.RandomBitGenerationException
import asia.hombre.kyber.interfaces.RandomProvider
import asia.hombre.kyber.internal.KyberMath
import kotlin.jvm.JvmStatic
import kotlin.jvm.JvmSynthetic

/**
 * A generator class for ML-KEM Keys.
 *
 * This class contains K-PKE.KeyGen() and ML-KEM.KeyGen() all according to NIST FIPS 203.
 *
 * @author Ron Lauren Hombre
 */
object KyberKeyGenerator {
    /**
     * Generate ML-KEM keys using the DefaultRandomProvider.
     *
     * This method is the ML-KEM.KeyGen() specified in NIST FIPS 203.
     *
     * @param parameter [KyberParameter] of the keys to be generated.
     * @param randomProvider (Optional) [RandomProvider] to use when generating the random and pke seed.
     * @return [KyberKEMKeyPair] - Contains the Encapsulation and Decapsulation Key.
     * @throws IllegalStateException when the generated random seed and pke seed are empty/null.
     */
    @JvmStatic
    fun generate(parameter: KyberParameter, randomProvider: RandomProvider = DefaultRandomProvider): KyberKEMKeyPair {
        return generate(
            parameter,
            ByteArray(KyberConstants.N_BYTES).apply { randomProvider.fillWithRandom(this) },
            ByteArray(KyberConstants.N_BYTES).apply { randomProvider.fillWithRandom(this) },
        )
    }

    /**
     * Internal Generate function for ML-KEM keys for testing purposes.
     *
     * This method is the ML-KEM.KeyGen_internal() specified in NIST FIPS 203.
     *
     * @param parameter [KyberParameter] of the keys to be generated.
     * @param randomSeed [ByteArray]
     * @param pkeSeed [ByteArray]
     * @return [KyberKEMKeyPair] - Contains the Encapsulation and Decapsulation Key.
     * @throws IllegalStateException when the generated random seed and pke seed are empty/null.
     */
    @JvmSynthetic
    internal fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray): KyberKEMKeyPair {
        if(randomSeed.fold(true) { acc, it -> acc and (it == 0.toByte()) } or
            pkeSeed.fold(true) { acc, it -> acc and (it == 0.toByte()) })
            throw RandomBitGenerationException()
        val pkeKeyPair = PKEGenerator.generate(parameter, pkeSeed)

        pkeSeed.fill(0) //Security feature

        val hash = SHA3_256().digest(pkeKeyPair.encryptionKey.fullBytes)

        return KyberKEMKeyPair(
            KyberEncapsulationKey(pkeKeyPair.encryptionKey),
            KyberDecapsulationKey(pkeKeyPair.decryptionKey, pkeKeyPair.encryptionKey, hash, randomSeed)
        )
    }

    /**
     * A generator class for K-PKE Keys.
     *
     * This subclass contains K-PKE.KeyGen() all according to NIST FIPS 203.
     *
     * @author Ron Lauren Hombre
     */
    internal object PKEGenerator {
        /**
         * Internal Generate function for K-PKE keys for testing purposes.
         *
         * This method is the K-PKE.KeyGen() specified in NIST FIPS 203.
         *
         * @param parameter [KyberParameter] of the keys to be generated.
         * @param byteArray Random [ByteArray] which is a seed.
         * @return [KyberPKEKeyPair] - Contains the Encryption and Decryption Key.
         */
        @JvmSynthetic
        fun generate(parameter: KyberParameter, byteArray: ByteArray): KyberPKEKeyPair {
            val seeds = SHA3_512().apply {
                update(byteArray)
                update(parameter.K.toByte())
            }.digest()

            //Security Feature
            byteArray.fill(0)

            val nttSeed = seeds.copyOfRange(0, 32)
            val cbdSeed = seeds.copyOfRange(32, 64)

            seeds.fill(0) //Security Feature

            val matrix = Array(parameter.K) { Array(parameter.K) { IntArray(KyberConstants.N) } }
            val secretVector = Array(parameter.K) { IntArray(KyberConstants.N) }
            val noiseVector = Array(parameter.K) { IntArray(KyberConstants.N) }

            val decryptionKeyBytes = ByteArray(parameter.DECRYPTION_KEY_LENGTH)

            for(i in 0 until parameter.K) {
                for(j in 0 until parameter.K)
                    matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, j.toByte(), i.toByte()))

                secretVector[i] = KyberMath.samplePolyCBD(
                    parameter.ETA1,
                    KyberMath.prf(parameter.ETA1, cbdSeed, i.toByte())
                )
                KyberMath.ntt(secretVector[i])
                KyberMath.byteEncodeInto(decryptionKeyBytes, i * KyberConstants.ENCODE_SIZE, secretVector[i], 12)

                noiseVector[i] = KyberMath.samplePolyCBD(
                    parameter.ETA1,
                    KyberMath.prf(parameter.ETA1, cbdSeed, (i + parameter.K).toByte())
                )
                KyberMath.ntt(noiseVector[i])
            }

            cbdSeed.fill(0) //Security Feature

            val systemVector = KyberMath.nttMatrixToVectorDot(matrix, secretVector, false)
            KyberMath.vectorAddition(systemVector, noiseVector)

            val encryptionKeyBytes = ByteArray(parameter.ENCRYPTION_KEY_LENGTH - 32) //Excluded nttSeed

            for(i in 0 until parameter.K) {
                KyberMath.byteEncodeInto(encryptionKeyBytes, i * KyberConstants.ENCODE_SIZE, systemVector[i], 12)
            }

            return KyberPKEKeyPair(
                KyberEncryptionKey(parameter, encryptionKeyBytes, nttSeed),
                KyberDecryptionKey(parameter, decryptionKeyBytes)
            )
        }
    }
}