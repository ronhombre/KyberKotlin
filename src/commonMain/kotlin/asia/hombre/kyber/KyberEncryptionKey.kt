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

import asia.hombre.kyber.exceptions.InvalidKyberKeyException
import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import asia.hombre.kyber.interfaces.KyberPKEKey
import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.core.Copyable
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * A class for ML-KEM Encryption Keys.
 *
 * This class contains the raw bytes of the Encryption Key and the accompanying NTT Seed.
 *
 * @constructor Stores the parameter, raw bytes of the Encryption Key, and the NTT Seed.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberEncryptionKey internal constructor(
    /**
     * The [KyberParameter] associated with this [KyberEncryptionKey].
     */
    override val parameter: KyberParameter,
    keyBytes: ByteArray,
    nttSeed: ByteArray
) : KyberPKEKey, Copyable<KyberEncryptionKey> {
    internal val keyBytes: ByteArray = keyBytes.copyOf()
    internal val nttSeed: ByteArray = nttSeed.copyOf()

    init {
        if(!KyberMath.byteEncode(KyberMath.byteDecode(keyBytes, 12), 12).contentEquals(keyBytes))
            throw InvalidKyberKeyException("Not modulus of " + KyberConstants.Q)
    }

    /**
     * All the bytes of the Encryption Key.
     *
     * @return [ByteArray]
     */
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() {
            val output = ByteArray(parameter.ENCAPSULATION_KEY_LENGTH)

            keyBytes.copyInto(output)
            nttSeed.copyInto(output, keyBytes.size)

            return output
        }

    companion object {
        /**
         * Wrap raw Encryption Key bytes into a [KyberEncryptionKey] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberEncryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Encryption Key is not of any ML-KEM variant.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberEncryptionKey {
            val keyLength = bytes.size - KyberConstants.N_BYTES
            return KyberEncryptionKey(
                KyberParameter.findByEncryptionKeySize(bytes.size),
                bytes.copyOfRange(0, keyLength),
                bytes.copyOfRange(keyLength, bytes.size)
            )
        }

        /**
         * Wrap raw Encryption Key hex values into a [KyberEncryptionKey] object.
         *
         * @param hexString [String] of hex values.
         * @return [KyberEncryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Encryption Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when there is a character that is not a hex value.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        fun fromHex(hexString: String): KyberEncryptionKey {
            return fromBytes(KyberMath.decodeHex(hexString))
        }

        /**
         * Wrap raw Base64 encoded Encryption Key into a [KyberEncryptionKey] object.
         *
         * @param base64String [String] of valid Base64 values.
         * @return [KyberEncryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Encryption Key is not of any ML-KEM variant.
         * @throws IllegalArgumentException when the Base64 is invalid.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, IllegalArgumentException::class)
        @OptIn(ExperimentalEncodingApi::class)
        fun fromBase64(base64String: String): KyberEncryptionKey {
            return fromBytes(Base64.decode(base64String))
        }
    }

    /**
     * Convert [KyberEncryptionKey] into a string of hex values.
     *
     * @param isUppercase
     * @return [String]
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun toHex(isUppercase: Boolean): String {
        return fullBytes.toHexString(if(isUppercase) HexFormat.UpperCase else HexFormat.Default)
    }

    /**
     * Convert [KyberEncryptionKey] into Base64 encoding.
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
     * @return [KyberEncryptionKey]
     */
    override fun copy(): KyberEncryptionKey {
        return KyberEncryptionKey(parameter, keyBytes.copyOf(), nttSeed.copyOf())
    }

    /**
     * Convert [KyberEncryptionKey] into a String.
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

        other as KyberEncryptionKey

        if (parameter != other.parameter) return false
        if (!keyBytes.contentEquals(other.keyBytes)) return false
        if (!nttSeed.contentEquals(other.nttSeed)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = parameter.hashCode()
        result = 31 * result + keyBytes.contentHashCode()
        result = 31 * result + nttSeed.contentHashCode()
        return result
    }
}