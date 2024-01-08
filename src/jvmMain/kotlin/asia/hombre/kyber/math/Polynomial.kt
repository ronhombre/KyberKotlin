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
import asia.hombre.kyber.security.KyberINDCPA
import java.util.*

internal class Polynomial {
    companion object {
        fun compressPoly(polyA: ShortArray, paramsK: Int): ByteArray {
            var polyA = polyA
            val t = ByteArray(8)
            polyA = polyConditionalSubQ(polyA)
            var rr = 0
            val r: ByteArray
            when (paramsK) {
                2, 3 -> {
                    r = ByteArray(Kyber.Params.POLY_COMPRESSED_BYTES_512) //Same with 768
                    for(i in 0 ..<(Kyber.Params.N / 8)) {
                        for(j in 0 ..<8)
                            t[j] = (((polyA[8 * i + j].toInt() shl 4) + Kyber.Params.Q / 2) / Kyber.Params.Q and 15).toByte()

                        r[rr + 0] = (t[0].toInt() or (t[1].toInt() shl 4)).toByte()
                        r[rr + 1] = (t[2].toInt() or (t[3].toInt() shl 4)).toByte()
                        r[rr + 2] = (t[4].toInt() or (t[5].toInt() shl 4)).toByte()
                        r[rr + 3] = (t[6].toInt() or (t[7].toInt() shl 4)).toByte()
                        rr += 4
                    }
                }

                else -> {
                    r = ByteArray(Kyber.Params.POLY_COMPRESSED_BYTES_1024)
                    for(i in 0 ..<(Kyber.Params.N / 8)) {
                        for(j in 0 ..<8)
                            t[j] = (((polyA[8 * i + j].toInt() shl 5) + Kyber.Params.Q / 2) / Kyber.Params.Q and 31).toByte()

                        r[rr + 0] = (t[0].toInt() shr 0 or (t[1].toInt() shl 5)).toByte()
                        r[rr + 1] = (t[1].toInt() shr 3 or (t[2].toInt() shl 2) or (t[3].toInt() shl 7)).toByte()
                        r[rr + 2] = (t[3].toInt() shr 1 or (t[4].toInt() shl 4)).toByte()
                        r[rr + 3] = (t[4].toInt() shr 4 or (t[5].toInt() shl 1) or (t[6].toInt() shl 6)).toByte()
                        r[rr + 4] = (t[6].toInt() shr 2 or (t[7].toInt() shl 3)).toByte()
                        rr += 5
                    }
                }
            }
            return r
        }

        fun decompressPoly(a: ByteArray, paramsK: Int): ShortArray {
            val r = ShortArray(Kyber.Params.POLY_BYTES)
            var aa = 0
            when (paramsK) {
                2, 3 -> {
                    for(i in 0 ..<(Kyber.Params.N / 2)) {
                        r[2 * i + 0] = (((a[aa].toInt() and 0xFF) and 15) * Kyber.Params.Q + 8 shr 4).toShort()
                        r[2 * i + 1] = (((a[aa].toInt() and 0xFF) shr 4) * Kyber.Params.Q + 8 shr 4).toShort()
                        aa += 1
                    }
                }

                else -> {
                    val t = LongArray(8)
                    for(i in 0 ..<(Kyber.Params.N / 8)) {
                        t[0] = ((a[aa + 0].toInt() and 0xFF) shr 0).toLong() and 0xFFL
                        t[1] = (((a[aa + 0].toInt() and 0xFF) shr 5).toByte()
                            .toInt() or ((a[aa + 1].toInt() and 0xFF) shl 3).toByte()
                            .toInt()).toLong() and 0xFFL
                        t[2] = ((a[aa + 1].toInt() and 0xFF) shr 2).toLong() and 0xFFL
                        t[3] = (((a[aa + 1].toInt() and 0xFF) shr 7).toByte()
                            .toInt() or ((a[aa + 2].toInt() and 0xFF) shl 1).toByte()
                            .toInt()).toLong() and 0xFFL
                        t[4] = (((a[aa + 2].toInt() and 0xFF) shr 4).toByte()
                            .toInt() or ((a[aa + 3].toInt() and 0xFF) shl 4).toByte()
                            .toInt()).toLong() and 0xFFL
                        t[5] = ((a[aa + 3].toInt() and 0xFF) shr 1).toLong() and 0xFFL
                        t[6] = (((a[aa + 3].toInt() and 0xFF) shr 6).toByte()
                            .toInt() or ((a[aa + 4].toInt() and 0xFF) shl 2).toByte()
                            .toInt()).toLong() and 0xFFL
                        t[7] = ((a[aa + 4].toInt() and 0xFF) shr 3).toLong() and 0xFFL
                        aa += 5
                        for (j in 0..<8)
                            r[8 * i + j] = ((t[j] and 31L) * Kyber.Params.Q + 16 shr 5).toShort()
                    }
                }
            }
            return r
        }

        fun polyToBytes(a: ShortArray): ByteArray {
            var a = a
            var t0: Int
            var t1: Int
            val r = ByteArray(Kyber.Params.POLY_BYTES)
            a = polyConditionalSubQ(a)
            for (i in 0..<Kyber.Params.N / 2) {
                t0 = (a[2 * i].toInt() and 0xFFFF)
                t1 = a[2 * i + 1].toInt() and 0xFFFF
                r[3 * i + 0] = (t0 shr 0).toByte()
                r[3 * i + 1] = ((t0 shr 8) or (t1 shl 4)).toByte()
                r[3 * i + 2] = (t1 shr 4).toByte()
            }
            return r
        }

        fun polyFromBytes(a: ByteArray): ShortArray {
            val r = ShortArray(Kyber.Params.POLY_BYTES)
            for (i in 0..<Kyber.Params.N / 2) {
                r[2 * i] =
                    (a[3 * i + 0].toInt() and 0xFF shr 0 or (a[3 * i + 1].toInt() and 0xFF shl 8) and 0xFFF).toShort()
                r[2 * i + 1] =
                    (a[3 * i + 1].toInt() and 0xFF shr 4 or (a[3 * i + 2].toInt() and 0xFF shl 4) and 0xFFF).toShort()
            }
            return r
        }

        fun polyFromData(msg: ByteArray): ShortArray {
            val r = ShortArray(Kyber.Params.N)
            var mask: Short
            for (i in 0..<Kyber.Params.N / 8) {
                for (j in 0..7) {
                    mask = (-1 * (msg[i].toInt() and 0xFF shr j and 1).toShort()).toShort()
                    r[8 * i + j] = (mask.toInt() and (((Kyber.Params.Q + 1) / 2).toShort()).toInt()).toShort()
                }
            }
            return r
        }

        fun polyToMsg(a: ShortArray): ByteArray {
            var a = a
            val msg = ByteArray(Kyber.Params.CPAPKE_BYTES)
            var t: Int
            a = polyConditionalSubQ(a)
            for (i in 0..<Kyber.Params.N / 8) {
                msg[i] = 0
                for (j in 0..7) {
                    t = (((a[8 * i + j].toInt() shl 1) + Kyber.Params.Q / 2) / Kyber.Params.Q and 1)
                    msg[i] = (msg[i].toInt() or (t shl j)).toByte()
                }
            }
            return msg
        }

        fun getNoisePoly(seed: ByteArray, nonce: Byte, paramsK: Int): ShortArray {
            val l: Int
            val p: ByteArray
            l = when (paramsK) {
                2 -> Kyber.Params.SAMPLE_NOISE_HIGH * Kyber.Params.N / 4
                else -> Kyber.Params.SAMPLE_NOISE_LOW * Kyber.Params.N / 4
            }
            p = KyberINDCPA.generatePRFByteArray(l, seed, nonce)
            return ByteOperations.generateCBDPoly(p, paramsK)
        }

        fun polyNTT(r: ShortArray): ShortArray {
            return NumberTheoreticTransform.ntt(r)
        }

        fun polyInvNTTMont(r: ShortArray): ShortArray {
            return NumberTheoreticTransform.invNTT(r)
        }

        fun polyBaseMulMont(polyA: ShortArray, polyB: ShortArray): ShortArray {
            for (i in 0..<Kyber.Params.N / 4) {
                val rx: ShortArray = NumberTheoreticTransform.baseMultiplier(
                    polyA[4 * i + 0], polyA[4 * i + 1],
                    polyB[4 * i + 0], polyB[4 * i + 1],
                    NumberTheoreticTransform.ZETAS[64 + i]
                )
                val ry: ShortArray = NumberTheoreticTransform.baseMultiplier(
                    polyA[4 * i + 2], polyA[4 * i + 3],
                    polyB[4 * i + 2], polyB[4 * i + 3],
                    (-1 * NumberTheoreticTransform.ZETAS[64 + i]).toShort()
                )
                polyA[4 * i + 0] = rx[0]
                polyA[4 * i + 1] = rx[1]
                polyA[4 * i + 2] = ry[0]
                polyA[4 * i + 3] = ry[1]
            }
            return polyA
        }

        fun polyToMont(polyR: ShortArray): ShortArray {
            for (i in 0 until Kyber.Params.N) {
                polyR[i] = ByteOperations.montgomeryReduce((polyR[i] * 1353).toLong())
            }
            return polyR
        }

        fun polyReduce(r: ShortArray): ShortArray {
            for (i in 0 until Kyber.Params.N) {
                r[i] = ByteOperations.barrettReduce(r[i])
            }
            return r
        }

        fun polyConditionalSubQ(r: ShortArray): ShortArray {
            for (i in 0 until Kyber.Params.N) {
                r[i] = ByteOperations.conditionalSubQ(r[i])
            }
            return r
        }

        fun polyAdd(polyA: ShortArray, polyB: ShortArray): ShortArray {
            for (i in 0 until Kyber.Params.N) {
                polyA[i] = (polyA[i] + polyB[i]).toShort()
            }
            return polyA
        }

        fun polySub(polyA: ShortArray, polyB: ShortArray): ShortArray {
            for (i in 0..<Kyber.Params.N) {
                polyA[i] = (polyA[i] - polyB[i]).toShort()
            }
            return polyA
        }

        fun generateNewPolyVector(paramsK: Int): Array<ShortArray> {
            return Array<ShortArray>(paramsK) { ShortArray(Kyber.Params.POLY_BYTES) }
        }

        fun compressPolyVector(a: Array<ShortArray>, paramsK: Int): ByteArray {
            polyVectorCSubQ(a, paramsK)
            var rr = 0
            val r: ByteArray
            val t: LongArray
            r = when (paramsK) {
                Kyber.KeySize.VARIANT_512.K -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_512)
                Kyber.KeySize.VARIANT_768.K -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_768)
                Kyber.KeySize.VARIANT_1024.K -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_1024)
                else -> throw RuntimeException("What?")
            }
            when (paramsK) {
                Kyber.KeySize.VARIANT_512.K,
                Kyber.KeySize.VARIANT_768.K -> {
                    t = LongArray(4)
                    for(i in 0..<paramsK)
                        for(j in 0..<(Kyber.Params.N / 4)) {
                            for(k in 0..<4)
                                t[k] = (((a[i][4 * j + k].toLong() shl 10) + (Kyber.Params.Q / 2).toLong()) / Kyber.Params.Q.toLong()) and 0x3ffL

                            r[rr + 0] = (t[0] shr 0).toByte()
                            r[rr + 1] = (t[0] shr 8 or (t[1] shl 2)).toByte()
                            r[rr + 2] = (t[1] shr 6 or (t[2] shl 4)).toByte()
                            r[rr + 3] = (t[2] shr 4 or (t[3] shl 6)).toByte()
                            r[rr + 4] = (t[3] shr 2).toByte()
                            rr += 5
                        }
                }
                else -> {
                    t = LongArray(8)
                    for(i in 0..<paramsK)
                        for(j in 0..<(Kyber.Params.N / 8)) {
                            for(k in 0..<8)
                                t[k] = (((a[i][(8 * j) + k].toLong() shl 11) + (Kyber.Params.Q / 2).toLong()) / Kyber.Params.Q.toLong()) and 0x7ffL

                            r[rr + 0] = (t[0] shr 0).toByte()
                            r[rr + 1] = (t[0] shr 8 or (t[1] shl 3)).toByte()
                            r[rr + 2] = (t[1] shr 5 or (t[2] shl 6)).toByte()
                            r[rr + 3] = (t[2] shr 2).toByte()
                            r[rr + 4] = (t[2] shr 10 or (t[3] shl 1)).toByte()
                            r[rr + 5] = (t[3] shr 7 or (t[4] shl 4)).toByte()
                            r[rr + 6] = (t[4] shr 4 or (t[5] shl 7)).toByte()
                            r[rr + 7] = (t[5] shr 1).toByte()
                            r[rr + 8] = (t[5] shr 9 or (t[6] shl 2)).toByte()
                            r[rr + 9] = (t[6] shr 6 or (t[7] shl 5)).toByte()
                            r[rr + 10] = (t[7] shr 3).toByte()
                            rr += 11
                        }
                }
            }
            return r
        }

        fun decompressPolyVector(a: ByteArray, paramsK: Int): Array<ShortArray> {
            val r = Array(paramsK) { ShortArray(Kyber.Params.POLY_BYTES) }
            var aa = 0
            val t: IntArray
            when (paramsK) {
                2, 3 -> {
                    t = IntArray(4) // has to be unsigned..
                    for(i in 0..<paramsK)
                        for(j in 0..<(Kyber.Params.N / 4)) {
                            t[0] = a[aa + 0].toInt() and 0xFF shr 0 or (a[aa + 1].toInt() and 0xFF shl 8)
                            t[1] = a[aa + 1].toInt() and 0xFF shr 2 or (a[aa + 2].toInt() and 0xFF shl 6)
                            t[2] = a[aa + 2].toInt() and 0xFF shr 4 or (a[aa + 3].toInt() and 0xFF shl 4)
                            t[3] = a[aa + 3].toInt() and 0xFF shr 6 or (a[aa + 4].toInt() and 0xFF shl 2)
                            aa += 5

                            for(k in 0..<4)
                                r[i][4 * j + k] = ((t[k] and 0x3FF).toLong() * Kyber.Params.Q.toLong() + 512 shr 10).toShort()
                        }
                }

                else -> {
                    t = IntArray(8) // has to be unsigned..
                    for(i in 0..<paramsK)
                        for(j in 0..<(Kyber.Params.N / 8)) {
                            t[0] = a[aa + 0].toInt() and 0xff shr 0 or (a[aa + 1].toInt() and 0xff shl 8)
                            t[1] = a[aa + 1].toInt() and 0xff shr 3 or (a[aa + 2].toInt() and 0xff shl 5)
                            t[2] =
                                a[aa + 2].toInt() and 0xff shr 6 or (a[aa + 3].toInt() and 0xff shl 2) or (a[aa + 4].toInt() and 0xff shl 10)
                            t[3] = a[aa + 4].toInt() and 0xff shr 1 or (a[aa + 5].toInt() and 0xff shl 7)
                            t[4] = a[aa + 5].toInt() and 0xff shr 4 or (a[aa + 6].toInt() and 0xff shl 4)
                            t[5] =
                                a[aa + 6].toInt() and 0xff shr 7 or (a[aa + 7].toInt() and 0xff shl 1) or (a[aa + 8].toInt() and 0xff shl 9)
                            t[6] = a[aa + 8].toInt() and 0xff shr 2 or (a[aa + 9].toInt() and 0xff shl 6)
                            t[7] = a[aa + 9].toInt() and 0xff shr 5 or (a[aa + 10].toInt() and 0xff shl 3)
                            aa += 11

                            for(k in 0..<8)
                                r[i][8 * j + k] = ((t[k] and 0x7FF).toLong() * Kyber.Params.Q.toLong() + 1024 shr 11).toShort()
                        }
                }
            }
            return r
        }

        fun polyVectorToBytes(polyA: Array<ShortArray>, paramsK: Int): ByteArray {
            val r = ByteArray(paramsK * Kyber.Params.POLY_BYTES)
            for (i in 0..<paramsK) {
                val byteA = polyToBytes(polyA[i])
                System.arraycopy(byteA, 0, r, i * Kyber.Params.POLY_BYTES, byteA.size)
            }
            return r
        }

        fun polyVectorFromBytes(polyA: ByteArray, paramsK: Int): Array<ShortArray> {
            val r = Array(paramsK) { ShortArray(Kyber.Params.POLY_BYTES) }
            for (i in 0..<paramsK) {
                val start: Int = i * Kyber.Params.POLY_BYTES
                val end: Int = (i + 1) * Kyber.Params.POLY_BYTES
                r[i] = polyFromBytes(Arrays.copyOfRange(polyA, start, end))
            }
            return r
        }

        fun polyVectorNTT(r: Array<ShortArray>, paramsK: Int): Array<ShortArray> {
            for (i in 0..<paramsK) {
                r[i] = polyNTT(r[i])
            }
            return r
        }

        fun polyVectorInvNTTMont(r: Array<ShortArray>, paramsK: Int): Array<ShortArray> {
            for (i in 0..<paramsK) {
                r[i] = polyInvNTTMont(r[i])
            }
            return r
        }

        fun polyVectorPointWiseAccMont(polyA: Array<ShortArray>, polyB: Array<ShortArray>, paramsK: Int): ShortArray {
            var r: ShortArray = polyBaseMulMont(polyA[0], polyB[0])
            for (i in 1..<paramsK) {
                val t: ShortArray = polyBaseMulMont(polyA[i], polyB[i])
                r = polyAdd(r, t)
            }
            return polyReduce(r)
        }

        fun polyVectorReduce(r: Array<ShortArray>, paramsK: Int): Array<ShortArray> {
            for (i in 0..<paramsK) {
                r[i] = polyReduce(r[i])
            }
            return r
        }

        fun polyVectorCSubQ(r: Array<ShortArray>, paramsK: Int): Array<ShortArray> {
            for (i in 0..<paramsK) {
                r[i] = polyConditionalSubQ(r[i])
            }
            return r
        }

        fun polyVectorAdd(polyA: Array<ShortArray>, polyB: Array<ShortArray>, paramsK: Int): Array<ShortArray> {
            for (i in 0..<paramsK) {
                polyA[i] = polyAdd(polyA[i], polyB[i])
            }
            return polyA
        }
    }
}