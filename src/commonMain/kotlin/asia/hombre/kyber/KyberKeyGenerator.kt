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

import asia.hombre.kyber.internal.KyberBackend
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
        require(randomSeed.size == KyberConstants.N_BYTES && pkeSeed.size == KyberConstants.N_BYTES)
        return KyberBackend.generate(parameter, randomSeed, pkeSeed)
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
            require(byteArray.size == KyberConstants.N_BYTES)
            return KyberBackend.generate(parameter, byteArray)
        }
    }
}