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

class KyberEncapsulationKey(override val key: KyberEncryptionKey) : KyberKEMKey {
    @get:JvmName("getFullBytes")
    val fullBytes: ByteArray
        get() = key.fullBytes
    companion object {
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBytes(bytes: ByteArray): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBytes(bytes))
        }

        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromHex(hexString: String): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromHex(hexString))
        }
        @JvmStatic
        @Throws(UnsupportedKyberVariantException::class)
        fun fromBase64(base64String: String): KyberEncapsulationKey {
            return KyberEncapsulationKey(KyberEncryptionKey.fromBase64(base64String))
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