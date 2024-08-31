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

    init {
        val coefficients = KyberMath.byteDecode(keyBytes, 12)
        for(c in coefficients)
            if(!KyberMath.isModuloOfQ(c))
                throw InvalidKyberKeyException("Not modulus of " + KyberConstants.Q)
    }

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
         * @throws InvalidKyberKeyException if the modulus check fails.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, InvalidKyberKeyException::class)
        fun fromBytes(bytes: ByteArray): KyberDecryptionKey {
            return KyberDecryptionKey(KyberParameter.findByDecryptionKeySize(bytes.size), bytes)
        }
    }

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberDecryptionKey]
     */
    fun copy(): KyberDecryptionKey {
        return KyberDecryptionKey(parameter, keyBytes)
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