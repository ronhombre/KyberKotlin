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

import asia.hombre.kyber.exceptions.EncapsulationException
import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import kotlin.jvm.JvmStatic
import kotlin.jvm.JvmSynthetic

/**
 * A generator class for ML-KEM Keys.
 *
 * This class contains K-PKE.KeyGen() and ML-KEM.KeyGen() all according to NIST FIPS 203.
 *
 * @author Ron Lauren Hombre
 */
class KyberKeyGenerator private constructor() {

    companion object {
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
            val secureRandom = SecureRandom()
            return generate(
                parameter,
                secureRandom.nextBytesOf(KyberConstants.N_BYTES),
                secureRandom.nextBytesOf(KyberConstants.N_BYTES)
            )
        }

        /**
         * Internal Generate function for ML-KEM keys for testing purposes.
         *
         * This method is the ML-KEM.KeyGen() specified in NIST FIPS 203.
         *
         * @param parameter [KyberParameter] of the keys to be generated.
         * @param randomSeed [ByteArray]
         * @param pkeSeed [ByteArray]
         * @return [KyberKEMKeyPair] - Contains the Encapsulation and Decapsulation Key.
         */
        @JvmSynthetic
        internal fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray): KyberKEMKeyPair {
            val sha3256 = SHA3_256()

            val pkeKeyPair = PKEGenerator.generate(parameter, pkeSeed)

            sha3256.update(pkeKeyPair.encryptionKey.fullBytes)

            val hash = sha3256.digest().copyOfRange(0, 32)

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
        internal class PKEGenerator {
            companion object {
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
                    val sha3512 = SHA3_512()

                    val seeds = sha3512.digest(byteArray)

                    //Security Features
                    byteArray.fill(0, 0, byteArray.size)

                    val nttSeed = seeds.copyOfRange(0, 32)
                    val cbdSeed = seeds.copyOfRange(32, 64)

                    seeds.fill(0, 0, seeds.size) //Security Feature

                    val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
                    val secretVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
                    val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

                    for((nonce, i) in (0..<parameter.K).withIndex()) {
                        for(j in 0..<parameter.K)
                            matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))

                        secretVector[i] = KyberMath.samplePolyCBD(
                            parameter.ETA1,
                            KyberMath.prf(parameter.ETA1, cbdSeed, nonce.toByte())
                        )
                        secretVector[i] = KyberMath.NTT(secretVector[i])

                        noiseVector[i] = KyberMath.samplePolyCBD(
                            parameter.ETA1,
                            KyberMath.prf(parameter.ETA1, cbdSeed, (nonce + parameter.K).toByte())
                        )
                        noiseVector[i] = KyberMath.NTT(noiseVector[i])
                    }

                    cbdSeed.fill(0, 0, cbdSeed.size) //Security Feature

                    //Transposed ? Old Kyber v3
                    val systemVector = KyberMath.vectorAddition(
                        KyberMath.nttMatrixToVectorDot(matrix, secretVector, true),
                        noiseVector
                    )

                    val encryptionKeyBytes = ByteArray(parameter.ENCRYPTION_KEY_LENGTH - KyberConstants.N_BYTES) //Excluded nttSeed
                    val decryptionKeyBytes = ByteArray(parameter.DECRYPTION_KEY_LENGTH)

                    for(i in 0..<parameter.K) {
                        //Security Features
                        for(j in 0..<parameter.K) matrix[i][j].fill(0, 0, matrix[i][j].size)
                        noiseVector[i].fill(0, 0, noiseVector[i].size)

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
    }
}