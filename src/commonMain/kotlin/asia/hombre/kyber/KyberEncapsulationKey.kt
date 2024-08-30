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
import org.kotlincrypto.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Encapsulation Keys.
 *
 * This class contains the raw bytes of the Decryption Key.
 *
 * @constructor Stores the Encryption Key which is the Encapsulation Key itself.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberEncapsulationKey internal constructor(
    /**
     * The [KyberEncryptionKey].
     */
    override val key: KyberEncryptionKey
) : KyberKEMKey {
    /**
     * All the bytes of the Encapsulation Key.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() = key.fullBytes.copyOf()
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
        @Deprecated("Conversion from hex values are up to the user.", level = DeprecationLevel.WARNING)
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
        @Deprecated("Conversion from base64 values are up to the user.", level = DeprecationLevel.WARNING,
            replaceWith = ReplaceWith(
                "KyberEncapsulationKey(KyberEncryptionKey.fromBase64(base64String))",
                "asia.hombre.kyber.KyberEncapsulationKey"
            )
        )
        fun fromBase64(base64String: String): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBase64(base64String))
        }
    }

    /**
     * Convert [KyberEncapsulationKey] into a string of hex values.
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
     * Convert [KyberEncapsulationKey] into Base64 encoding.
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
     * @return [KyberEncapsulationKey]
     */
    fun copy(): KyberEncapsulationKey {
        return KyberEncapsulationKey(key.copy())
    }

    /**
     * Encapsulates this [KyberEncapsulationKey] into a [KyberCipherText] and generates a Secret Key.
     *
     * This method is the ML-KEM.Encaps() specified in NIST FIPS 203.
     *
     * @return [KyberEncapsulationResult] - Contains the Cipher Text and the generated Secret Key.
     */
    fun encapsulate(): KyberEncapsulationResult {
        return KyberAgreement.encapsulate(this, SecureRandom().nextBytesOf(KyberConstants.N_BYTES))
    }

    /**
     * Convert [KyberEncapsulationKey] into a String.
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

        other as KyberEncapsulationKey

        return key == other.key
    }

    override fun hashCode(): Int {
        return key.hashCode()
    }
}