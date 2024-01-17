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
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

class KyberEncryptionKey(
    override val parameter: KyberParameter,
    override val keyBytes: ByteArray,
    val nttSeed: ByteArray) : KyberPKEKey {
        @get:JvmName("getFullBytes")
        val fullBytes: ByteArray
            get() {
                val output = ByteArray(parameter.ENCAPSULATION_KEY_LENGTH)

                keyBytes.copyInto(output)
                nttSeed.copyInto(output, keyBytes.size)

                return output
            }

        companion object {
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

            @JvmStatic
            @Throws(UnsupportedKyberVariantException::class)
            fun fromHex(hexString: String): KyberEncryptionKey {
                return fromBytes(KyberMath.decodeHex(hexString))
            }

            @JvmStatic
            @Throws(UnsupportedKyberVariantException::class)
            @OptIn(ExperimentalEncodingApi::class)
            fun fromBase64(base64String: String): KyberEncryptionKey {
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