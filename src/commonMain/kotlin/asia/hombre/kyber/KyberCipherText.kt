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

import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import asia.hombre.kyber.internal.KyberAgreement
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Cipher Texts.
 *
 * This class contains the raw bytes of the Cipher Text.
 *
 * @constructor Stores the parameter, encoded coefficients, and encoded terms of the Cipher Text.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberCipherText internal constructor(
    /**
     * The [KyberParameter] associated with this [KyberCipherText].
     */
    val parameter: KyberParameter,
    encodedCoefficients: ByteArray,
    encodedTerms: ByteArray) {

    internal val encodedCoefficients: ByteArray = encodedCoefficients.copyOf()
    internal val encodedTerms: ByteArray = encodedTerms.copyOf()
    /**
     * All the bytes of the Cipher Text.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() {
            val output = ByteArray(parameter.CIPHERTEXT_LENGTH)

            encodedCoefficients.copyInto(output, 0)
            encodedTerms.copyInto(output, encodedCoefficients.size)

            return output
        }

    companion object {
        /**
         * Wrap raw Cipher Text bytes into a [KyberCipherText] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberCipherText]
         * @throws UnsupportedKyberVariantException when the length of the Cipher Text is not of any ML-KEM variant.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberCipherText {
            val parameter = KyberParameter.findByCipherTextSize(bytes.size)

            val encodedCoefficientsSize = KyberConstants.N_BYTES * (parameter.DU * parameter.K)

            return KyberCipherText(
                KyberParameter.findByCipherTextSize(bytes.size),
                bytes.copyOfRange(0, encodedCoefficientsSize),
                bytes.copyOfRange(encodedCoefficientsSize, bytes.size)
            )
        }
    }

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberCipherText]
     */
    fun copy(): KyberCipherText {
        return KyberCipherText(this.parameter, encodedCoefficients, encodedTerms)
    }

    /**
     * Decapsulates this [KyberCipherText] and recovers the Shared Secret Key.
     *
     * This method is the ML-KEM.Decaps() specified in NIST FIPS 203.
     *
     * Equivalent method with [KyberDecapsulationKey.decapsulate].
     *
     * @param decapsulationKey your [KyberDecapsulationKey].
     * @return [ByteArray] - The generated Shared Secret Key, which is the same one generated by the sender.
     */
    fun decapsulate(decapsulationKey: KyberDecapsulationKey): ByteArray {
        return KyberAgreement.decapsulate(decapsulationKey, this)
    }

    /**
     * Deep equality check.
     *
     * @return [Boolean]
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KyberCipherText

        if (parameter != other.parameter) return false
        if (!encodedCoefficients.contentEquals(other.encodedCoefficients)) return false
        if (!encodedTerms.contentEquals(other.encodedTerms)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = parameter.hashCode()
        result = 31 * result + encodedCoefficients.contentHashCode()
        result = 31 * result + encodedTerms.contentHashCode()
        return result
    }
}