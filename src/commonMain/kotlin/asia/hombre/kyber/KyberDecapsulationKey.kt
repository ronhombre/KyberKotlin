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
import asia.hombre.kyber.internal.KyberMath
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Decapsulation Keys.
 *
 * This class contains the raw bytes of the Decapsulation Key.
 *
 * @constructor Stores the Encryption Key, Decryption Key, Hash, and Random Seed composing the Decapsulation Key.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberDecapsulationKey internal constructor(
    /**
     * The [KyberDecryptionKey].
     */
    override val key: KyberDecryptionKey,
    /**
     * The [KyberEncryptionKey].
     */
    val encryptionKey: KyberEncryptionKey,
    hash: ByteArray,
    randomSeed: ByteArray
) : KyberKEMKey {
    internal val hash: ByteArray = hash.copyOf()
    internal val randomSeed: ByteArray = randomSeed.copyOf()

    /**
     * The [KyberParameter] associated with this [KyberDecapsulationKey].
     */
    val parameter = key.parameter

    /**
     * All the bytes of the Cipher Text.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() {
            val output = ByteArray(key.parameter.DECAPSULATION_KEY_LENGTH)

            key.keyBytes.copyInto(output)
            encryptionKey.fullBytes.copyInto(output, key.keyBytes.size)
            hash.copyInto(output, key.keyBytes.size + encryptionKey.fullBytes.size)
            randomSeed.copyInto(output, output.size - randomSeed.size)

            return output
        }

    companion object {
        /**
         * Wrap raw Decapsulation Key bytes into a [KyberDecapsulationKey] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberDecapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Decapsulation Key is not of any ML-KEM variant.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberDecapsulationKey {
            val parameter = KyberParameter.findByDecapsulationKeySize(bytes.size)

            val decryptionKey = KyberDecryptionKey.fromBytes(bytes.copyOfRange(0, parameter.DECRYPTION_KEY_LENGTH))
            val encryptionKey = KyberEncryptionKey.fromBytes(bytes.copyOfRange(parameter.DECRYPTION_KEY_LENGTH, parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH))
            val hash = bytes.copyOfRange(bytes.size - (2 * KyberConstants.N_BYTES), bytes.size - KyberConstants.N_BYTES)
            val randomSeed = bytes.copyOfRange(bytes.size - KyberConstants.N_BYTES, bytes.size)

            return KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed)
        }

        /**
         * Wrap raw Decapsulation Key hex values into a [KyberDecapsulationKey] object.
         *
         * @param hexString [String] of hex values.
         * @return [KyberDecapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Decapsulation Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when there is a character that is not a hex value.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        @Deprecated("Conversion from hex values are up to the user.", level = DeprecationLevel.WARNING)
        fun fromHex(hexString: String): KyberDecapsulationKey {
            return fromBytes(KyberMath.decodeHex(hexString))
        }

        /**
         * Wrap raw Base64 encoded Decapsulation Key into a [KyberDecapsulationKey] object.
         *
         * @param base64String [String] of valid Base64 values.
         * @return [KyberDecapsulationKey]
         * @throws UnsupportedKyberVariantException when the length of the Decapsulation Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when the Base64 is invalid.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        @OptIn(ExperimentalEncodingApi::class)
        @Deprecated("Conversion from base64 values are up to the user.", level = DeprecationLevel.WARNING,
            replaceWith = ReplaceWith(
                "fromBytes(Base64.decode(base64String))",
                "asia.hombre.kyber.KyberDecapsulationKey.Companion.fromBytes",
                "kotlin.io.encoding.Base64"
            )
        )
        fun fromBase64(base64String: String): KyberDecapsulationKey {
            return fromBytes(Base64.decode(base64String))
        }
    }

    /**
     * Convert [KyberDecapsulationKey] into a string of hex values.
     *
     * @param isUppercase
     * @return [String]
     */
    @Deprecated("Conversion to hex values are up to the user.", level = DeprecationLevel.WARNING, replaceWith =
        ReplaceWith("fullBytes.toHexString(if (isUppercase) HexFormat.UpperCase else HexFormat.Default)")
    )
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(isUppercase: Boolean): String {
        return fullBytes.toHexString(if(isUppercase) HexFormat.UpperCase else HexFormat.Default)
    }

    /**
     * Convert [KyberDecapsulationKey] into Base64 encoding.
     *
     * @return [String]
     */
    @Deprecated("Conversion to base64 values are up to the user.", level = DeprecationLevel.WARNING,
        replaceWith = ReplaceWith("Base64.encode(fullBytes)", "kotlin.io.encoding.Base64")
    )
    @OptIn(ExperimentalEncodingApi::class)
    override fun toBase64(): String {
        return Base64.encode(fullBytes)
    }

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberDecapsulationKey]
     */
    fun copy(): KyberDecapsulationKey {
        return KyberDecapsulationKey(key.copy(), encryptionKey, hash.copyOf(), randomSeed.copyOf())
    }

    /**
     * Convert [KyberDecapsulationKey] into a String.
     *
     * Deprecated and usage is forbidden!
     *
     * @return empty "" [String]
     */
    @Deprecated("This leaks the contents and is a risk when used in logging.", level =  DeprecationLevel.ERROR)
    override fun toString(): String {
        return ""
    }

    /**
     * Deep equality check.
     *
     * @return [Boolean]
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KyberDecapsulationKey

        if (key != other.key) return false
        if (encryptionKey != other.encryptionKey) return false
        if (!hash.contentEquals(other.hash)) return false
        if (!randomSeed.contentEquals(other.randomSeed)) return false
        if (parameter != other.parameter) return false

        return true
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + encryptionKey.hashCode()
        result = 31 * result + hash.contentHashCode()
        result = 31 * result + randomSeed.contentHashCode()
        result = 31 * result + parameter.hashCode()
        return result
    }
}