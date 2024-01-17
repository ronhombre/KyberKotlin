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
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

class KyberDecapsulationKey(
    override val key: KyberDecryptionKey,
    val encryptionKey: KyberEncryptionKey,
    val hash: ByteArray,
    val randomSeed: ByteArray) : KyberKEMKey {
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

            @JvmStatic
            @Throws(UnsupportedKyberVariantException::class)
            fun fromHex(hexString: String): KyberDecapsulationKey {
                return fromBytes(KyberMath.decodeHex(hexString))
            }

            @JvmStatic
            @Throws(UnsupportedKyberVariantException::class)
            @OptIn(ExperimentalEncodingApi::class)
            fun fromBase64(base64String: String): KyberDecapsulationKey {
                return fromBytes(Base64.decode(base64String))
            }
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun toHex(): String {
            return fullBytes.toHexString(HexFormat.UpperCase)
        }

        @OptIn(ExperimentalEncodingApi::class)
        override fun toBase64(): String {
            return Base64.encode(fullBytes)
        }

        override fun toString(): String {
            return toHex()
        }
    }