//Copyright 2023 Ron Lauren Hombre
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//       and included as LICENSE.txt in this Project.
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
package asia.hombre.kyber.math

import asia.hombre.kyber.provider.Kyber
import java.util.*

internal class ByteOperations {

    companion object {
        fun convertByteTo32BitUnsignedInt(x: ByteArray): ULong {
            var r = (x[0].toULong() and 0xFFu)
            r = r or ((x[1].toULong() and 0xFFu) shl 8)
            r = r or ((x[2].toULong() and 0xFFu) shl 16)
            r = r or ((x[3].toULong() and 0xFFu) shl 24)
            return r
        }

        fun convertByteTo24BitUnsignedInt(x: ByteArray): ULong {
            var r = (x[0].toULong() and 0xFFu)
            r = r or ((x[1].toULong() and 0xFFu) shl 8)
            r = r or ((x[2].toULong() and 0xFFu) shl 16)
            return r
        }

        fun generateCBDPoly(buf: ByteArray, paramsK: Int): ShortArray {
            var t: ULong
            var d: ULong = 0u
            var a: Int
            var b: Int
            val r = ShortArray(Kyber.Params.POLY_BYTES)
            when (paramsK) {
                2 -> {
                    for(i in 0..<(Kyber.Params.N / 4)) {
                        t = convertByteTo24BitUnsignedInt(
                            Arrays.copyOfRange(
                                buf,
                                3 * i, buf.size
                            )
                        )
                        for(j in 0..<Kyber.Params.SAMPLE_NOISE_HIGH) {
                            d += t shr j and 0x00249249uL
                        }
                        for(j in 0..<4) {
                            a = (d shr (6 * j + 0) and 0x7uL).toShort().toInt()
                            b = (d shr (6 * j + Kyber.Params.SAMPLE_NOISE_HIGH) and 0x7uL).toShort().toInt()
                            r[4 * i + j] = (a - b).toShort()
                        }
                    }
                }

                else -> {
                    for(i in 0..<(Kyber.Params.N / 8)) {
                        t = convertByteTo32BitUnsignedInt(
                            Arrays.copyOfRange(
                                buf,
                                4 * i, buf.size
                            )
                        )/*
                        d = t and 0x55555555uL
                        d += (t shr 1 and 0x55555555uL)*/
                        for(j in 0..<Kyber.Params.SAMPLE_NOISE_LOW) {
                            d += t shr j and 0x55555555uL
                        }
                        for(j in 0..<8) {
                            a = (d shr 4 * j + 0 and 0x3uL).toShort().toInt()
                            b = (d shr 4 * j + Kyber.Params.SAMPLE_NOISE_LOW and 0x3uL).toShort().toInt()
                            r[(8 * i) + j] = (a - b).toShort()
                        }
                    }
                }
            }
            return r
        }

        fun montgomeryReduce(a: Long): Short {
            val u = (a * Kyber.Params.Q_PRIME).toShort()
            var t = (u * Kyber.Params.Q)
            t = (a - t).toInt()
            t = t shr 16
            return t.toShort()
        }

        fun barrettReduce(a: Short): Short {
            var t: Short
            val shift = 1L shl 26
            t = (((shift + Kyber.Params.Q / 2) / Kyber.Params.Q) * a shr 26).toShort()
            t = (t * Kyber.Params.Q).toShort()
            return (a - t).toShort()
        }

        fun conditionalSubQ(a: Short): Short {
            var a = a
            a = (a - Kyber.Params.Q).toShort()
            a = (a + ((a.toInt() shr 15) and Kyber.Params.Q)).toShort()
            return a
        }
    }
}