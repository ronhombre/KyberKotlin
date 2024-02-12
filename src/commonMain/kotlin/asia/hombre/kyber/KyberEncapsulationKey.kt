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
import asia.hombre.kyber.interfaces.KyberKEMKey
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Encapsulation Keys.
 *
 * This class contains the raw bytes of the Decryption Key.
 *
 * @param key [KyberEncryptionKey]
 * @constructor Stores the Encryption Key which is the Encapsulation Key itself.
 * @author Ron Lauren Hombre
 */
class KyberEncapsulationKey internal constructor(override val key: KyberEncryptionKey) : KyberKEMKey {
    /**
     * All the bytes of the Encapsulation Key.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() = key.fullBytes
    companion object {
        /**
         * Wrap raw Encapsulation Key bytes into a [KyberEncapsulationKey] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberEncapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Encapsulation Key is not of any ML-KEM variant.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBytes(bytes))
        }

        /**
         * Wrap raw Encapsulation Key hex values into a [KyberEncapsulationKey] object.
         *
         * @param hexString [String] of hex values.
         * @return [KyberEncapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Encapsulation Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when there is a character that is not a hex value.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        fun fromHex(hexString: String): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromHex(hexString))
        }

        /**
         * Wrap raw Base64 encoded Encapsulation Key into a [KyberEncapsulationKey] object.
         *
         * @param base64String [String] of valid Base64 values.
         * @return [KyberEncapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Encapsulation Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when the Base64 is invalid.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        fun fromBase64(base64String: String): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBase64(base64String))
        }
    }

    /**
     * Convert [KyberEncapsulationKey] into a string of hex values.
     *
     * @param format [HexFormat] of the hex string.
     * @return [String]
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(format: HexFormat): String {
        return fullBytes.toHexString(format)
    }

    /**
     * Convert [KyberEncapsulationKey] into a string of hex values.
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
     * Convert [KyberEncapsulationKey] into Base64 encoding.
     *
     * @return [String]
     */
    @OptIn(ExperimentalEncodingApi::class)
    override fun toBase64(): String {
        return Base64.encode(fullBytes)
    }

    /**
     * Convert [KyberEncapsulationKey] into a String.
     *
     * This wraps [toHex], so they return the same values.
     *
     * @return [String]
     */
    override fun toString(): String {
        return toHex()
    }
}