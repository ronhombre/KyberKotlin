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
import asia.hombre.kyber.interfaces.KyberPKEKey
import asia.hombre.kyber.internal.KyberMath
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Decryption Keys.
 *
 * This class contains the raw bytes of the Decryption Key.
 *
 * @constructor Stores the parameter and raw bytes of the Decryption Key.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberDecryptionKey internal constructor(
    /**
     * The [KyberParameter] associated with this [KyberDecryptionKey].
     */
    override val parameter: KyberParameter,
    keyBytes: ByteArray
) : KyberPKEKey {
    internal val keyBytes: ByteArray = keyBytes.copyOf()

    /**
     * All the bytes of the Decryption Key.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() = keyBytes.copyOf()

    companion object {
        /**
         * Wrap raw Decryption Key bytes into a [KyberDecryptionKey] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberDecryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Decryption Key is not of any ML-KEM variant.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberDecryptionKey {
            return KyberDecryptionKey(KyberParameter.findByDecryptionKeySize(bytes.size), bytes)
        }

        /**
         * Wrap raw Decryption Key hex values into a [KyberDecryptionKey] object.
         *
         * @param hexString [String] of hex values.
         * @return [KyberDecryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Decryption Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when there is a character that is not a hex value.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        fun fromHex(hexString: String): KyberDecryptionKey {
            return fromBytes(KyberMath.decodeHex(hexString))
        }

        /**
         * Wrap raw Base64 encoded Decryption Key into a [KyberDecryptionKey] object.
         *
         * @param base64String [String] of valid Base64 values.
         * @return [KyberDecryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Decryption Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when the Base64 is invalid.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        @OptIn(ExperimentalEncodingApi::class)
        fun fromBase64(base64String: String): KyberDecryptionKey {
            return fromBytes(Base64.decode(base64String))
        }
    }

    /**
     * Convert [KyberDecryptionKey] into a string of hex values.
     *
     * @param isUppercase
     * @return [String]
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(isUppercase: Boolean): String {
        return fullBytes.toHexString(if(isUppercase) HexFormat.UpperCase else HexFormat.Default)
    }

    /**
     * Convert [KyberDecryptionKey] into Base64 encoding.
     *
     * @return [String]
     */
    @OptIn(ExperimentalEncodingApi::class)
    override fun toBase64(): String {
        return Base64.encode(fullBytes)
    }

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberDecryptionKey]
     */
    fun copy(): KyberDecryptionKey {
        return KyberDecryptionKey(parameter, keyBytes.copyOf())
    }

    /**
     * Convert [KyberDecryptionKey] into a String.
     *
     * This wraps [toHex], so they return the same values.
     *
     * @return [String]
     */
    override fun toString(): String {
        return toHex()
    }

    /**
     * Deep equality check.
     *
     * @return [Boolean]
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KyberDecryptionKey

        if (parameter != other.parameter) return false
        if (!keyBytes.contentEquals(other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = parameter.hashCode()
        result = 31 * result + keyBytes.contentHashCode()
        return result
    }
}