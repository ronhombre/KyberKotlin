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

enum class KyberParameter(val K: Int, val ETA1: Int, val ETA2: Int, val DU: Int, val DV: Int) {
    ML_KEM_512(2, 3, 2, 10, 4),
    ML_KEM_768(3, 2, 2, 10, 4),
    ML_KEM_1024(4, 2, 2, 11, 5);

    @JvmField
    val CIPHERTEXT_LENGTH: Int = KyberConstants.N_BYTES * ((DU * K) + DV)

    @JvmField
    val DECRYPTION_KEY_LENGTH: Int = KyberConstants.ENCODE_SIZE * K

    @JvmField
    val ENCRYPTION_KEY_LENGTH: Int = DECRYPTION_KEY_LENGTH + KyberConstants.N_BYTES

    @JvmField
    val ENCAPSULATION_KEY_LENGTH: Int = ENCRYPTION_KEY_LENGTH

    @JvmField
    val DECAPSULATION_KEY_LENGTH: Int = ENCAPSULATION_KEY_LENGTH + DECRYPTION_KEY_LENGTH + (2 * KyberConstants.N_BYTES)

    companion object {
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByCipherTextSize(size: Int): KyberParameter {
            return when(size) {
                ML_KEM_512.CIPHERTEXT_LENGTH -> ML_KEM_512
                ML_KEM_768.CIPHERTEXT_LENGTH -> ML_KEM_768
                ML_KEM_1024.CIPHERTEXT_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Cipher Text size is either bigger or smaller than expected.")
            }
        }

        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByEncryptionKeySize(size: Int): KyberParameter {
            return when(size) {
                ML_KEM_512.ENCAPSULATION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.ENCAPSULATION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.ENCAPSULATION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Encryption/Encapsulation Key size is either bigger or smaller than expected.")
            }
        }

        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByEncapsulationKeySize(size: Int): KyberParameter {
            return findByEncryptionKeySize(size)
        }

        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByDecryptionKeySize(size: Int): KyberParameter {
            return when(size) {
                ML_KEM_512.DECRYPTION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.DECRYPTION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.DECRYPTION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Decryption Key size is either bigger or smaller than expected.")
            }
        }

        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun findByDecapsulationKeySize(size: Int): KyberParameter {
            return when(size) {
                ML_KEM_512.DECAPSULATION_KEY_LENGTH -> ML_KEM_512
                ML_KEM_768.DECAPSULATION_KEY_LENGTH -> ML_KEM_768
                ML_KEM_1024.DECAPSULATION_KEY_LENGTH -> ML_KEM_1024
                else -> throw UnsupportedKyberVariantException("Decapsulation Key size is either bigger or smaller than expected.")
            }
        }
    }
}