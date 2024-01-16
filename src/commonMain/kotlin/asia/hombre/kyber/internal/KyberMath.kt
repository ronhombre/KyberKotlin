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

package asia.hombre.kyber.internal

import asia.hombre.kyber.KyberConstants
import org.kotlincrypto.hash.sha3.SHAKE128
import org.kotlincrypto.hash.sha3.SHAKE256
import kotlin.jvm.JvmSynthetic
import kotlin.math.*

internal class KyberMath {

    internal companion object {
        @get:JvmSynthetic
        val Boolean.int
            get() = (if (this) 1 else 0)

        @JvmSynthetic
        fun bitsToBytes(bits: BooleanArray): ByteArray {
            val byteArray = ByteArray(ceil(bits.size / 8.0).toInt())

            for(i in bits.indices) {
                val bIndex = floor(i / 8.0).toInt()
                byteArray[bIndex] = (byteArray[bIndex].toInt() or (bits[i].int shl (i % 8))).toByte()
            }

            return byteArray
        }

        @JvmSynthetic
        fun bytesToBits(bytes: ByteArray): BooleanArray {
            val bitArray = BooleanArray(bytes.size * 8)

            for(i in bytes.indices) {
                var byteVal = bytes[i]
                for(j in 0..<8) {
                    bitArray[(8 * i) + j] = (byteVal.toUInt() % 2u) == 1u
                    byteVal = (byteVal.toInt() ushr 1).toByte()
                }
            }

            return bitArray
        }

        @JvmSynthetic
        fun compress(shorts: ShortArray, bitSize: Int): ShortArray {
            val compressed = ShortArray(shorts.size)

            for(i in shorts.indices)
                compressed[i] = (((1 shl bitSize) * shorts[i]) / KyberConstants.Q.toDouble()).roundToInt().toShort()

            return compressed
        }

        @JvmSynthetic
        fun decompress(shorts: ShortArray, bitSize: Int): ShortArray {
            val decompressed = ShortArray(shorts.size)

            for (i in shorts.indices)
                decompressed[i] = ((KyberConstants.Q * shorts[i]) / (1 shl bitSize).toDouble()).roundToInt().toShort()

            return decompressed
        }

        @JvmSynthetic
        fun byteEncode(shorts: ShortArray, bitSize: Int): ByteArray {
            if(bitSize > UShort.SIZE_BITS)
                throw ArithmeticException("There are not enough bits to encode! Bit Size: $bitSize is too big!")

            val bits = BooleanArray(shorts.size * bitSize)

            for(i in shorts.indices) {
                shorts[i] = moduloOf(shorts[i], KyberConstants.Q)
                for(j in 0..<bitSize) {
                    bits[(i * bitSize) + j] = ((shorts[i].toInt() ushr j) and 1) == 1
                }
            }

            return bitsToBytes(bits)
        }

        @JvmSynthetic
        fun byteDecode(byteArray: ByteArray, bitSize: Int): ShortArray {
            val bits = bytesToBits(byteArray)
            val shorts = ShortArray(bits.size / bitSize)
            for(i in shorts.indices) {
                for(j in 0..<(bitSize)) {
                    val value = shorts[i].toInt() or (bits[(i * bitSize) + j].int shl j)
                    var mod = pow(2, bitSize + 1).toShort()

                    if((j + 1) == bitSize)
                        mod = KyberConstants.Q.toShort()

                    shorts[i] = moduloOf(value, mod)
                }
            }

            return shorts
        }

        @JvmSynthetic
        fun sampleNTT(bytes: ByteArray): ShortArray {
            val nttCoefficients = ShortArray(KyberConstants.N)

            var i = 0
            var j = 0
            while(j < KyberConstants.N) {
                val d1 = ((bytes[i].toInt() and 0xFF) or ((bytes[i + 1].toInt() and 0xFF) shl 8) and 0xFFF)
                val d2 = ((bytes[i + 1].toInt() and 0xFF) shr 4 or ((bytes[i + 2].toInt() and 0xFF) shl 4) and 0xFFF)

                if(d1 < KyberConstants.Q) {
                    nttCoefficients[j] = d1.toShort()
                    j++
                }
                if(d2 < KyberConstants.Q && j < KyberConstants.N) {
                    nttCoefficients[j] = d2.toShort()
                    j++
                }

                i += 3
            }

            return nttCoefficients
        }

        @JvmSynthetic
        fun samplePolyCBD(eta: Int, bytes: ByteArray): ShortArray {
            val f = ShortArray(KyberConstants.N)
            val bits = bytesToBits(bytes)

            for(i in 0..<KyberConstants.N) {
                var x: Short = 0
                var y: Short = 0
                for(j in 0..<eta) {
                    x = (x + bits[(2 * i * eta) + j].int).toShort()
                    y = (y + bits[(2 * i * eta) + eta + j].int).toShort()
                }
                f[i] = diffOf(x, y)
            }

            return f
        }

        @JvmSynthetic
        fun reverseBits(x: Int): UByte {
            return (((1 and x) shl 6) or
                    (((1 shl 1) and x) shl 4) or
                    (((1 shl 2) and x) shl 2) or
                    (((1 shl 3) and x)) or
                    (((1 shl 4) and x) ushr 2) or
                    (((1 shl 5) and x) ushr 4) or
                    (((1 shl 6) and x) ushr 6)).toUByte()
        }

        //Functionally equivalent to pow_mod(b, e, mod) in Python, except values are kept positive
        @JvmSynthetic
        fun powMod(b: Int, e: Int, m: Int): Long {
            if(e == 0) //b^0 = 1
                return 1L
            else if(e < 0) //Inverse
                return modMulInv(b, e.absoluteValue, m)

            var c = 1L

            for(i in 0..<e)
                c = (b * c) % m

            return c
        }

        @JvmSynthetic
        private fun pow(a: Int, b: Int): Long {
            var out = 1L

            for(i in 0..<b) {
                out *= a
            }

            return out
        }

        //Modified Extended Euclidean Algorithm
        @JvmSynthetic
        private fun modMulInv(b: Int, e: Int, m: Int): Long {
            var s = 0L
            var r: Long = m.toLong()
            var oldS = 1L
            var oldR = pow(b, e)

            while(r != 0L) {
                val quotient = oldR / r
                val tempR = r
                r = oldR - (quotient * r)
                oldR = tempR
                val tempS = s
                s = oldS - (quotient * s)
                oldS = tempS
            }

            if(oldS < 0)
                oldS += m

            return oldS
        }

        @JvmSynthetic
        fun NTT(polynomials: ShortArray): ShortArray {
            val output = polynomials.copyOf()

            var k = 1
            var len = KyberConstants.N shr 1

            while(len >= 2) {
                for(start in 0..<KyberConstants.N step (2 * len)) {
                    for(j in start..<(start + len)) {
                        val t = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], output[j + len])
                        output[j + len] = diffOf(output[j], t)
                        output[j] = sumOf(output[j], t)
                    }
                    k++
                }

                len = len shr 1
            }

            return output
        }

        @JvmSynthetic
        fun invNTT(nttPolynomials: ShortArray): ShortArray {
            val output = nttPolynomials.copyOf()

            var k = (KyberConstants.N shr 1) - 1
            var len = 2

            while(len <= (KyberConstants.N shr 1)) {
                for(start in 0..<KyberConstants.N step (2 * len)) {
                    for(j in start..<(start + len)) {
                        val t = output[j]
                        output[j] = sumOf(t, output[j + len])
                        output[j + len] = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], diffOf(output[j + len], t))
                    }
                    k--
                }

                len = len shl 1
            }

            for(i in output.indices)
                output[i] = productOf(output[i].toInt(), 3303)

            return output
        }

        @JvmSynthetic
        fun productOf(a: Number, b: Number): Short {
            return moduloOf(a.toInt() * b.toInt(), KyberConstants.Q)
        }

        @JvmSynthetic
        fun sumOf(a: Number, b: Number): Short {
            return moduloOf(a.toInt() + b.toInt(), KyberConstants.Q)
        }

        @JvmSynthetic
        fun diffOf(a: Number, b: Number): Short {
            return moduloOf(a.toInt() - b.toInt(), KyberConstants.Q)
        }

        @JvmSynthetic
        fun multiplyNTTs(ntt1: ShortArray, ntt2: ShortArray): ShortArray {
            val multipliedNtt = ShortArray(KyberConstants.N)

            for(i in 0..<(KyberConstants.N shr 1)) {
                multipliedNtt[2 * i] = sumOf(
                    productOf(
                        ntt1[2 * i],
                        ntt2[2 * i]
                    ),
                    productOf(
                        productOf(
                            ntt1[(2 * i) + 1],
                            ntt2[(2 * i) + 1]
                        ),
                        KyberConstants.PRECOMPUTED_GAMMAS_TABLE[i]
                    )
                )
                multipliedNtt[(2 * i) + 1] = sumOf(
                    productOf(
                        ntt1[2 * i],
                        ntt2[(2 * i) + 1]
                    ),
                    productOf(
                        ntt1[(2 * i) + 1],
                        ntt2[2 * i]
                    )
                )
            }

            return multipliedNtt
        }

        @JvmSynthetic
        fun xof(seed: ByteArray, byte1: Byte, byte2: Byte): ByteArray {
            val shake128 = SHAKE128(672)

            shake128.update(seed)
            shake128.update(byte1)
            shake128.update(byte2)

            return shake128.digest()
        }

        @JvmSynthetic
        fun prf(eta: Int, seed: ByteArray, byte: Byte): ByteArray {
            val shake256 = SHAKE256((KyberConstants.N shr 2) * eta)

            shake256.update(seed)
            shake256.update(byte)

            return shake256.digest()
        }

        @JvmSynthetic
        fun nttMatrixToVectorDot(matrix: Array<Array<ShortArray>>, vector: Array<ShortArray>, isTransposed: Boolean = false): Array<ShortArray> {
            val result = Array(vector.size) { ShortArray(KyberConstants.N) }

            for(i in matrix.indices)
                for(j in vector.indices) {
                    val a = if(isTransposed) j else i
                    val b = if(isTransposed) i else j
                    result[i] = vectorToVectorAdd(result[i], multiplyNTTs(matrix[a][b], vector[j]))
                }

            return result
        }

        @JvmSynthetic
        fun vectorAddition(v1: Array<ShortArray>, v2: Array<ShortArray>): Array<ShortArray> {
            val result = Array(v1.size) { ShortArray(v2[0].size) }

            for(i in v1.indices)
                result[i] = vectorToVectorAdd(v1[i], v2[i])

            return result
        }

        @JvmSynthetic
        fun vectorToVectorAdd(v1: ShortArray, v2: ShortArray): ShortArray {
            val result = ShortArray(v1.size)

            for(i in v1.indices)
                result[i] = sumOf(v1[i], v2[i])

            return result
        }

        @JvmSynthetic
        fun moduloOf(value: Number, modulo: Number): Short {
            val shortedValue = value.toInt()
            val shortedModulo = modulo.toShort()
            return if(shortedValue < 0) (shortedModulo - (abs(shortedValue) % shortedModulo)).toShort()
            else (shortedValue % shortedModulo).toShort()
        }
    }
}