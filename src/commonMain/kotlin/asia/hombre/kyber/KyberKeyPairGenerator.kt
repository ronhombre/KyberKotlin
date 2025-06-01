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
import asia.hombre.kyber.internal.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import kotlin.jvm.JvmSynthetic

internal class KyberKeyPairGenerator {

    companion object {
        @JvmSynthetic
        fun generate(parameter: KyberParameter): KyberKEMKeyPair {
            return generate(
                parameter,
                SecureRandom.generateSecureBytes(KyberConstants.N_BYTES),
                SecureRandom.generateSecureBytes(KyberConstants.N_BYTES)
            )
        }

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

        internal class PKEGenerator {
            companion object {
                @JvmSynthetic
                fun generate(parameter: KyberParameter, byteArray: ByteArray): KyberPKEKeyPair {
                    val sha3512 = SHA3_512()

                    sha3512.update(byteArray)

                    val seeds = sha3512.digest(byteArrayOf(parameter.K.toByte()))

                    val nttSeed = seeds.copyOfRange(0, 32)
                    val cbdSeed = seeds.copyOfRange(32, 64)

                    val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
                    val secretVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
                    val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

                    for((nonce, i) in (0..<parameter.K).withIndex()) {
                        for(j in 0..<parameter.K) {
                            matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, j.toByte(), i.toByte()))
                        }

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

                    //Transposed ? Old Kyber v3
                    val systemVector = KyberMath.vectorAddition(
                        KyberMath.nttMatrixToVectorDot(matrix, secretVector, false),
                        noiseVector
                    )

                    val encryptionKeyBytes = ByteArray(parameter.ENCRYPTION_KEY_LENGTH - KyberConstants.N_BYTES) //Excluded nttSeed
                    val decryptionKeyBytes = ByteArray(parameter.DECRYPTION_KEY_LENGTH)

                    for(i in 0..<parameter.K) {
                        KyberMath.byteEncode(systemVector[i], 12)
                            .copyInto(encryptionKeyBytes, i * KyberConstants.ENCODE_SIZE)
                        KyberMath.byteEncode(secretVector[i], 12)
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