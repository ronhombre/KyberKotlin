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

import asia.hombre.kyber.exceptions.InvalidKyberKeyException
import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import asia.hombre.kyber.interfaces.KyberPKEKey
import asia.hombre.kyber.internal.KyberMath
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
class KyberEncryptionKey internal constructor(
    /**
     * The [KyberParameter] associated with this [KyberEncryptionKey].
     */
    override val parameter: KyberParameter,
    keyBytes: ByteArray,
    nttSeed: ByteArray
) : KyberPKEKey {
    internal val keyBytes: ByteArray = keyBytes.copyOf()
    internal val nttSeed: ByteArray = nttSeed.copyOf()

    init {
        val coefficients = KyberMath.fastByteDecode(keyBytes, 12)
        for(c in coefficients)
            if(!KyberMath.isModuloOfQ(c))
                throw InvalidKyberKeyException("Not modulus of " + KyberConstants.Q)
    }

    /**
     * A copy of the Encryption Key in bytes.
     *
     * Note that this is different from the Encapsulation key but is effectively the same.
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
         * Copies raw Encryption Key bytes into a [KyberEncryptionKey] object.
         *
         * @param bytes [ByteArray]
         * @return [KyberEncryptionKey]
         * @throws UnsupportedKyberVariantException when the length of the Encryption Key is not of any ML-KEM variant.
         * @throws InvalidKyberKeyException if the modulus check fails.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, InvalidKyberKeyException::class)
        fun fromBytes(bytes: ByteArray): KyberEncryptionKey {
            val keyLength = bytes.size - KyberConstants.N_BYTES
            return KyberEncryptionKey(
                KyberParameter.findByEncryptionKeySize(bytes.size),
                bytes.copyOfRange(0, keyLength),
                bytes.copyOfRange(keyLength, bytes.size)
            )
        }
    }

    /**
     * Create an independent deep copy from an untrusted source.
     *
     * @return [KyberEncryptionKey]
     */
    fun copy(): KyberEncryptionKey {
        return KyberEncryptionKey(parameter, keyBytes, nttSeed)
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