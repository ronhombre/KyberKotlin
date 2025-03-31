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
import asia.hombre.kyber.interfaces.KyberKEMKey
import asia.hombre.kyber.internal.KyberAgreement
import org.kotlincrypto.random.CryptoRand
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
         * @throws InvalidKyberKeyException if the modulus check fails.
         */
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class, InvalidKyberKeyException::class)
        fun fromBytes(bytes: ByteArray): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBytes(bytes))
        }
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
     * Encapsulates this [KyberEncapsulationKey] into a [KyberCipherText] and generates a Shared Secret Key.
     *
     * This method is the ML-KEM.Encaps() specified in NIST FIPS 203.
     *
     * @return [KyberEncapsulationResult] - Contains the Cipher Text and the generated Shared Secret Key.
     */
    fun encapsulate(): KyberEncapsulationResult {
        return KyberAgreement.encapsulate(this, ByteArray(KyberConstants.N_BYTES).apply { CryptoRand.Default.nextBytes(this) })
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