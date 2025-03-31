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
import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.random.CryptoRand
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmStatic
import kotlin.jvm.JvmSynthetic

/**
 * A generator class for ML-KEM Keys.
 *
 * This class contains K-PKE.KeyGen() and ML-KEM.KeyGen() all according to NIST FIPS 203.
 *
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
object KyberKeyGenerator {
    /**
     * Generate ML-KEM keys.
     *
     * This method is the ML-KEM.KeyGen() specified in NIST FIPS 203.
     *
     * @param parameter [KyberParameter] of the keys to be generated.
     * @return [KyberKEMKeyPair] - Contains the Encapsulation and Decapsulation Key.
     */
    @JvmStatic
    fun generate(parameter: KyberParameter): KyberKEMKeyPair {
        return generate(
            parameter,
            ByteArray(KyberConstants.N_BYTES).apply { CryptoRand.Default.nextBytes(this) },
            ByteArray(KyberConstants.N_BYTES).apply { CryptoRand.Default.nextBytes(this) },
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
     */
    @JvmSynthetic
    internal fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray): KyberKEMKeyPair {
        val pkeKeyPair = PKEGenerator.generate(parameter, pkeSeed)

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
            val seeds = SHA3_512().digest(byteArray)

            //Security Feature
            byteArray.fill(0)

            val nttSeed = seeds.copyOfRange(0, 32)
            val cbdSeed = seeds.copyOfRange(32, 64)

            seeds.fill(0) //Security Feature

            val matrix = Array(parameter.K) { Array(parameter.K) { IntArray(KyberConstants.N) } }
            val secretVector = Array(parameter.K) { IntArray(KyberConstants.N) }
            val noiseVector = Array(parameter.K) { IntArray(KyberConstants.N) }

            for((nonce, i) in (0..<parameter.K).withIndex()) {
                for(j in 0..<parameter.K)
                    matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))

                secretVector[i] = KyberMath.samplePolyCBD(
                    parameter.ETA1,
                    KyberMath.prf(parameter.ETA1, cbdSeed, nonce.toByte())
                )
                secretVector[i] = KyberMath.ntt(secretVector[i])

                noiseVector[i] = KyberMath.samplePolyCBD(
                    parameter.ETA1,
                    KyberMath.prf(parameter.ETA1, cbdSeed, (nonce + parameter.K).toByte())
                )
                noiseVector[i] = KyberMath.ntt(noiseVector[i])
            }

            cbdSeed.fill(0) //Security Feature

            val systemVector = KyberMath.vectorAddition(
                KyberMath.nttMatrixToVectorDot(matrix, secretVector, true),
                noiseVector
            )

            val encryptionKeyBytes = ByteArray(parameter.ENCRYPTION_KEY_LENGTH - KyberConstants.N_BYTES) //Excluded nttSeed
            val decryptionKeyBytes = ByteArray(parameter.DECRYPTION_KEY_LENGTH)

            for(i in 0..<parameter.K) {
                //Security Features
                for(j in 0..<parameter.K) matrix[i][j].fill(0)
                noiseVector[i].fill(0)

                KyberMath.byteEncode(KyberMath.montVectorToVector(systemVector[i]), 12)
                    .copyInto(encryptionKeyBytes, i * KyberConstants.ENCODE_SIZE)
                KyberMath.byteEncode(KyberMath.montVectorToVector(secretVector[i]), 12)
                    .copyInto(decryptionKeyBytes, i * KyberConstants.ENCODE_SIZE)
            }

            return KyberPKEKeyPair(
                KyberEncryptionKey(parameter, encryptionKeyBytes, nttSeed),
                KyberDecryptionKey(parameter, decryptionKeyBytes)
            )
        }
    }
}