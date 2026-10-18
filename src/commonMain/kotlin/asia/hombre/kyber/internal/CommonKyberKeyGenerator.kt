/*
 * Copyright 2026 Ron Lauren Hombre
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

package asia.hombre.kyber.internal

import asia.hombre.kyber.*

import asia.hombre.keccak.api.SHA3_256
import asia.hombre.keccak.api.SHA3_512
import asia.hombre.keccak.api.SHAKE128
import asia.hombre.keccak.api.SHAKE256
import asia.hombre.kyber.exceptions.RandomBitGenerationException
import asia.hombre.kyber.interfaces.RandomProvider
import kotlin.jvm.JvmStatic
import kotlin.jvm.JvmSynthetic

/**
 * A generator class for ML-KEM Keys.
 *
 * This class contains K-PKE.KeyGen() and ML-KEM.KeyGen() all according to NIST FIPS 203.
 *
 * @author Ron Lauren Hombre
 */
internal object CommonKyberKeyGenerator {
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
        val output = ByteArray(parameter.DECAPSULATION_KEY_LENGTH)
        val bytes = ByteBuffer(output)
        val pkeKeyPair = PKEGenerator.generate(
            parameter, pkeSeed, bytes.slice(0, parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH)
        )
        val ek = pkeKeyPair.encryptionKey.bytes
        SHA3_256().apply { update(ek.array, ek.offset, ek.size) }.digest()
            .copyInto(output, output.size - 2 * KyberConstants.N_BYTES)
        randomSeed.copyInto(output, output.size - KyberConstants.N_BYTES)

        return KyberKEMKeyPair(
            KyberEncapsulationKey(pkeKeyPair.encryptionKey),
            KyberDecapsulationKey(parameter, bytes)
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
            return generate(parameter, byteArray, ByteBuffer(ByteArray(parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH)))
        }

        fun generate(parameter: KyberParameter, byteArray: ByteArray, output: ByteBuffer): KyberPKEKeyPair {
            require(output.size == parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH)
            val seeds = SHA3_512().apply {
                update(byteArray)
                update(parameter.K.toByte())
            }.digest()

            byteArray.fill(0) //Security Feature

            val decryptionKeyBytes = output.slice(0, parameter.DECRYPTION_KEY_LENGTH)
            val encryptionKeyBytes = output.slice(parameter.DECRYPTION_KEY_LENGTH)
            val nttSeed = encryptionKeyBytes.slice(parameter.DECRYPTION_KEY_LENGTH)
            seeds.copyInto(nttSeed.array, nttSeed.offset, 0, KyberConstants.N_BYTES)
            val cbdSeed = ByteBuffer(seeds, KyberConstants.N_BYTES)

            val secretVector = Array(parameter.K) { IntArray(KyberConstants.N) }
            val xof = SHAKE128()
            val prf = SHAKE256()

            for(i in 0 until parameter.K) {
                KyberMath.samplePolyCBDInto(
                    secretVector[i],
                    parameter.ETA1,
                    prf.apply {
                        update(cbdSeed.array, cbdSeed.offset, cbdSeed.size)
                        update(i.toByte())
                    }.stream().nextBytes(KyberConstants.QUART_N * parameter.ETA1)
                )
                KyberMath.ntt(secretVector[i])
                KyberMath.byteEncodeInto(decryptionKeyBytes.array, decryptionKeyBytes.offset + i * KyberConstants.ENCODE_SIZE, secretVector[i])
            }

            val matrixElement = IntArray(KyberConstants.N)
            val systemVectorElement = IntArray(KyberConstants.N)

            for(i in 0 until parameter.K) {
                KyberMath.samplePolyCBDInto(
                    systemVectorElement,
                    parameter.ETA1,
                    prf.apply {
                        update(cbdSeed.array, cbdSeed.offset, cbdSeed.size)
                        update((i + parameter.K).toByte())
                    }.stream().nextBytes(KyberConstants.QUART_N * parameter.ETA1)
                )
                KyberMath.ntt(systemVectorElement)

                for(j in 0 until parameter.K) {
                    KyberMath.sampleNTTInto(
                        matrixElement,
                        xof.apply {
                            update(nttSeed.array, nttSeed.offset, nttSeed.size)
                            update(j.toByte())
                            update(i.toByte())
                        }.stream()
                    )
                    KyberMath.multiplyNTTsInto(systemVectorElement, matrixElement, secretVector[j])
                }

                for(k in 0 until KyberConstants.N) {
                    systemVectorElement[k] = KyberMath.barrettReduce(systemVectorElement[k])
                }

                KyberMath.byteEncodeInto(encryptionKeyBytes.array, encryptionKeyBytes.offset + i * KyberConstants.ENCODE_SIZE, systemVectorElement)
            }

            systemVectorElement.fill(0) //Security Feature
            seeds.fill(0) //Security Feature

            return KyberPKEKeyPair(
                KyberEncryptionKey(parameter, encryptionKeyBytes),
                KyberDecryptionKey(parameter, decryptionKeyBytes)
            )
        }
    }
}
