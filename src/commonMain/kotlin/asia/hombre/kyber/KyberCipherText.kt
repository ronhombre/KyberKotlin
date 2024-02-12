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
import asia.hombre.kyber.interfaces.Convertible
import asia.hombre.kyber.internal.KyberMath
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Cipher Texts.
 *
 * This class contains the raw bytes of the Cipher Text.
 *
 * @param parameter [KyberParameter]
 * @constructor Stores the parameter, encoded coefficients, and encoded terms of the Cipher Text.
 * @author Ron Lauren Hombre
 */
class KyberCipherText internal constructor(val parameter: KyberParameter, internal val encodedCoefficients: ByteArray, internal val encodedTerms: ByteArray): Convertible {
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

        /**
         * Wrap raw Cipher Text hex values into a [KyberCipherText] object.
         *
         * @param hexString [String] of hex values.
         * @return [KyberCipherText]
         * @throws UnsupportedKyberVariantException when the length of the Cipher Text is not of any ML-KEM variant.
         * @throws IllegalArgumentException when there is a character that is not a hex value.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        fun fromHex(hexString: String): KyberCipherText {
            return fromBytes(KyberMath.decodeHex(hexString))
        }

        /**
         * Wrap raw Base64 encoded Cipher Text into a [KyberCipherText] object.
         *
         * @param base64String [String] of valid Base64 values.
         * @return [KyberCipherText]
         * @throws UnsupportedKyberVariantException when the length of the Cipher Text is not of any ML-KEM variant.
         * @throws IllegalArgumentException when the Base64 is invalid.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        @OptIn(ExperimentalEncodingApi::class)
        fun fromBase64(base64String: String): KyberCipherText {
            return fromBytes(Base64.decode(base64String))
        }
    }

    /**
     * Convert [KyberCipherText] into a string of hex values.
     *
     * @param format [HexFormat] of the hex string.
     * @return [String]
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(format: HexFormat): String {
        return fullBytes.toHexString(format)
    }

    /**
     * Convert [KyberCipherText] into a string of hex values.
     *
     * Format is defaulted to [HexFormat.UpperCase].
     *
     * @return [String]
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(): String {
        return toHex(HexFormat.UpperCase)
    }

    /**
     * Convert [KyberCipherText] into Base64 encoding.
     *
     * @return [String]
     */
    @OptIn(ExperimentalEncodingApi::class)
    override fun toBase64(): String {
        return Base64.encode(fullBytes)
    }

    /**
     * Convert [KyberCipherText] into a String.
     *
     * This wraps [toHex], so they return the same values.
     *
     * @return [String]
     */
    override fun toString(): String {
        return toHex()
    }
}