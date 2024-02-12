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

import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * Parameter sets for ML-KEM.
 *
 * This class contains the defined parameter values for each set of ML-KEM according to NIST FIPS 203.
 *
 * @author Ron Lauren Hombre
 */
enum class KyberParameter(val K: Int, val ETA1: Int, val ETA2: Int, val DU: Int, val DV: Int) {
    /**
     * ML-KEM-512 (RBG Strength: 128, NIST Security Category: 1).
     */
    ML_KEM_512(2, 3, 2, 10, 4),

    /**
     * ML-KEM-768 (RBG Strength: 192, NIST Security Category: 3).
     */
    ML_KEM_768(3, 2, 2, 10, 4),

    /**
     * ML-KEM-1024 (RBG Strength: 256, NIST Security Category: 5).
     */
    ML_KEM_1024(4, 2, 2, 11, 5);

    /**
     * The byte length of the Cipher Text for the parameter set.
     */
    @JvmField
    val CIPHERTEXT_LENGTH: Int = KyberConstants.N_BYTES * ((DU * K) + DV)

    /**
     * The byte length of the Decryption Key for the parameter set.
     */
    @JvmField
    val DECRYPTION_KEY_LENGTH: Int = KyberConstants.ENCODE_SIZE * K

    /**
     * The byte length of the Encryption Key for the parameter set.
     */
    @JvmField
    val ENCRYPTION_KEY_LENGTH: Int = DECRYPTION_KEY_LENGTH + KyberConstants.N_BYTES

    /**
     * The byte length of the Encapsulation Key for the parameter set.
     */
    @JvmField
    val ENCAPSULATION_KEY_LENGTH: Int = ENCRYPTION_KEY_LENGTH

    /**
     * The byte length of the Decapsulation Key for the parameter set.
     */
    @JvmField
    val DECAPSULATION_KEY_LENGTH: Int = ENCAPSULATION_KEY_LENGTH + DECRYPTION_KEY_LENGTH + (2 * KyberConstants.N_BYTES)

    companion object {
        /**
         * Find parameter set used based on the byte length of the Cipher Text.
         *
         * @param length [Int]
         * @return [KyberParameter]
         * @throws UnsupportedKyberVariantException when the byte length does not match any parameter set.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByCipherTextSize(length: Int): KyberParameter {
            return when(length) {
                ML_KEM_512.CIPHERTEXT_LENGTH -> ML_KEM_512
                ML_KEM_768.CIPHERTEXT_LENGTH -> ML_KEM_768
                ML_KEM_1024.CIPHERTEXT_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Cipher Text byte length is either bigger or smaller than expected.")
            }
        }

        /**
         * Find parameter set used based on the byte length of the Encryption Key.
         *
         * @param length [Int]
         * @return [KyberParameter]
         * @throws UnsupportedKyberVariantException when the byte length does not match any parameter set.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByEncryptionKeySize(length: Int): KyberParameter {
            return when(length) {
                ML_KEM_512.ENCAPSULATION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.ENCAPSULATION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.ENCAPSULATION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Encryption Key byte length is either bigger or smaller than expected.")
            }
        }

        /**
         * Find parameter set used based on the byte length of the Encapsulation Key.
         *
         * @param length [Int]
         * @return [KyberParameter]
         * @throws UnsupportedKyberVariantException when the byte length does not match any parameter set.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByEncapsulationKeySize(length: Int): KyberParameter {
            return try {
                findByEncryptionKeySize(length)
            } catch (exception: UnsupportedKyberVariantException) {
                throw UnsupportedKyberVariantException("Encapsulation Key byte length is either bigger or smaller than expected.")
            }
        }

        /**
         * Find parameter set used based on the byte length of the Decryption Key.
         *
         * @param length [Int]
         * @return [KyberParameter]
         * @throws UnsupportedKyberVariantException when the byte length does not match any parameter set.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByDecryptionKeySize(length: Int): KyberParameter {
            return when(length) {
                ML_KEM_512.DECRYPTION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.DECRYPTION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.DECRYPTION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Decryption Key byte length is either bigger or smaller than expected.")
            }
        }

        /**
         * Find parameter set used based on the byte length of the Decapsulation Key.
         *
         * @param length [Int]
         * @return [KyberParameter]
         * @throws UnsupportedKyberVariantException when the byte length does not match any parameter set.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByDecapsulationKeySize(length: Int): KyberParameter {
            return when(length) {
                ML_KEM_512.DECAPSULATION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.DECAPSULATION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.DECAPSULATION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Decapsulation Key byte length is either bigger or smaller than expected.")
            }
        }
    }
}