/*
 * Copyright 2026 Ron Lauren Hombre
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

import kotlin.jvm.JvmSynthetic

@Suppress("unused")
object TestHelper {
    @JvmSynthetic
    fun expandBytesAsBits(bytes: ByteArray): IntArray {
        val bitArray = IntArray(bytes.size * 8)

        for(i in bytes.indices) {
            val byte = bytes[i].toInt()
            bitArray[(8 * i)] = byte and 1
            bitArray[(8 * i) + 1] = (byte shr 1) and 1
            bitArray[(8 * i) + 2] = (byte shr 2) and 1
            bitArray[(8 * i) + 3] = (byte shr 3) and 1
            bitArray[(8 * i) + 4] = (byte shr 4) and 1
            bitArray[(8 * i) + 5] = (byte shr 5) and 1
            bitArray[(8 * i) + 6] = (byte shr 6) and 1
            bitArray[(8 * i) + 7] = (byte shr 7) and 1
        }

        return bitArray
    }

    @JvmSynthetic
    @Throws(IllegalArgumentException::class)
    fun decodeHex(string: String): ByteArray {
        var hexString = string

        if(string.length % 2 == 1)
            hexString += '0' //Append a 0 if the hex is not even to fit into a byte.

        if(string.contains(Regex("[^A-Fa-f0-9]")))
            throw IllegalArgumentException("String cannot contain characters that is not hex characters.")

        return hexString.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}