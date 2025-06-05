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

package asia.hombre.kyber.internal

import asia.hombre.keccak.api.SHAKE128
import asia.hombre.keccak.api.SHAKE256
import asia.hombre.keccak.streams.HashOutputStream
import asia.hombre.kyber.KyberConstants
import kotlin.jvm.JvmSynthetic
import kotlin.math.absoluteValue
import kotlin.math.min

internal object KyberMath {

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
    fun decompress(shorts: IntArray, bitSize: Int) {
        for (i in shorts.indices)
            shorts[i] = ((KyberConstants.Q * shorts[i]) + (1 shl (bitSize - 1))) shr bitSize
    }

    /**
     * O(n * bitSize / 8) compared to O(n * n * bitSize) with the standard algorithm.
     * Significantly reduced iterations and minimized memory operations to bare minimum.
     */
    @JvmSynthetic
    fun fastByteDecode(bytes: ByteArray, bitSize: Int, offset: Int = 0, length: Int = bytes.size - offset): IntArray {
        val result = IntArray(length * 8 / bitSize)
        val lastIndex = offset + length - 1
        var byteIndex = offset
        var usableBits = 8
        var currentByte = bytes[byteIndex].toInt() and 0xFF

        for (i in result.indices) {
            var accumulator = 0
            var ingestedBits = 0

            while (ingestedBits < bitSize) {
                val canIngest = min(usableBits, bitSize - ingestedBits)
                val mask = 0xFF shr (8 - canIngest)

                accumulator = accumulator or ((currentByte and mask) shl ingestedBits)
                currentByte = currentByte shr canIngest
                usableBits -= canIngest
                ingestedBits += canIngest

                if (usableBits == 0 && byteIndex < lastIndex) {
                    byteIndex++
                    currentByte = bytes[byteIndex].toInt() and 0xFF
                    usableBits = 8
                }
            }
            result[i] = accumulator
        }
        return result
    }

    /**
     * Reduced memory copy operations compared to byteEncode(vector, bitSize)
     */
    @JvmSynthetic
    fun byteEncodeInto(output: ByteArray, destIndex: Int, vector: IntArray, bitSize: Int) {
        var outputIndex = 0
        var bitIndex = 0
        var temp = 0
        for(i in vector.indices) {
            val value = barrettReduce(montgomeryReduce(vector[i]))

            for(j in 0 until bitSize) {
                temp = temp or (((value shr j) and 1) shl bitIndex++)
                if(bitIndex == 8) {
                    output[destIndex + outputIndex++] = temp.toByte()
                    bitIndex = 0
                    temp = 0
                }
            }
        }
    }

    /**
     * Reduced memory copy operations compared to byteEncode(compress(vector, bitSize), bitSize)
     */
    @JvmSynthetic
    fun compressAndEncodeInto(output: ByteArray, destIndex: Int, vector: IntArray, bitSize: Int) {
        val mask = 1 shl bitSize
        var outputIndex = 0
        var bitIndex = 0
        var temp = 0
        for(i in vector.indices) {
            val value = ((mask * montgomeryReduce(vector[i])) + KyberConstants.Q_HALF) / KyberConstants.Q

            for(j in 0 until bitSize) {
                temp = temp or (((value shr j) and 1) shl bitIndex++)
                if(bitIndex == 8) {
                    output[destIndex + outputIndex++] = temp.toByte()
                    bitIndex = 0
                    temp = 0
                }
            }
        }
    }

    @JvmSynthetic
    fun expandMuse(bytes: ByteArray): IntArray {
        val shorts = IntArray(bytes.size * 8)
        val decompressConstant = toMontgomeryForm(KyberConstants.Q_HALF + 1)

        for(i in bytes.indices) {
            val byte = bytes[i].toInt()
            for(j in 0 until 8) shorts[(i * 8) + j] = ((byte shr j) and 1) * decompressConstant
        }

        return shorts
    }

    @JvmSynthetic
    fun sampleNTT(byteStream: HashOutputStream): IntArray {
        val nttCoefficients = IntArray(KyberConstants.N)

        val buffer = ByteArray(3)

        var j = 0
        while(j < KyberConstants.N) {
            byteStream.nextBytes(buffer) //Fill byte buffer

            val d1 = ((buffer[0].toInt() and 0xFF) or (buffer[1].toInt() shl 8) and 0xFFF)
            val d2 = ((buffer[1].toInt() and 0xFF) shr 4 or (buffer[2].toInt() shl 4) and 0xFFF)

            if(d1 < KyberConstants.Q) nttCoefficients[j++] = toMontgomeryForm(d1)
            if(d2 < KyberConstants.Q && j < KyberConstants.N) nttCoefficients[j++] = toMontgomeryForm(d2)
        }

        return nttCoefficients
    }

    @JvmSynthetic
    fun samplePolyCBD(eta: Int, bytes: ByteArray): IntArray {
        val f = IntArray(KyberConstants.N)
        val bits = expandBytesAsBits(bytes)

        for(i in 0 until KyberConstants.N) {
            val offset = 2 * i * eta
            var x = 0
            var y = 0
            for(j in 0 until eta) {
                x += bits[offset + j]
                y += bits[offset + eta + j]
            }
            f[i] = toMontgomeryForm(x - y)
        }

        return f
    }

    @JvmSynthetic
    fun ntt(polynomials: IntArray): IntArray {
        val output = polynomials

        var k = 1
        var len = KyberConstants.N shr 1

        while(len >= 2) {
            for(start in 0 until KyberConstants.N step (2 * len)) {
                for(j in start until (start + len)) {
                    val temp = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], output[j + len])
                    output[j + len] = output[j] - temp
                    output[j] = output[j] + temp
                }
                k++
            }

            len = len shr 1
        }

        return output
    }

    @JvmSynthetic
    fun nttInv(nttPolynomials: IntArray): IntArray {
        val output = nttPolynomials

        var k = (KyberConstants.N shr 1) - 1
        var len = 2

        while(len <= (KyberConstants.N shr 1)) {
            for(start in 0 until KyberConstants.N step (2 * len)) {
                for(j in start until (start + len)) {
                    val temp = output[j]
                    output[j] = temp + output[j + len]
                    output[j + len] = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], output[j + len] - temp)
                }
                k--
            }

            len = len shl 1
        }

        for(i in output.indices)
            output[i] = productOf(output[i], 512) // toMontgomeryForm(3303) = 512

        return output
    }

    @JvmSynthetic
    fun productOf(a: Int, b: Int): Int = montgomeryReduce(a * b)

    @JvmSynthetic
    fun multiplyNTTs(ntt1: IntArray, ntt2: IntArray, offset1: Int = 0): IntArray {
        val multipliedNtt = IntArray(KyberConstants.N)

        for(i in 0 until (KyberConstants.N shr 1)) {
            val a = i shl 1
            val b = a + 1
            //Karatsuba Multiplication from 5 multiplication operations to 4 which also helps with reducing Montgomery Reductions.
            val x = productOf(ntt1[a + offset1], ntt2[a])
            val y = productOf(ntt1[b + offset1], ntt2[b])
            multipliedNtt[a] = productOf(y, KyberConstants.PRECOMPUTED_GAMMAS_TABLE[i]) + x
            multipliedNtt[b] = productOf(ntt1[a + offset1] + ntt1[b + offset1], ntt2[a] + ntt2[b]) - x - y
        }

        return multipliedNtt
    }

    @JvmSynthetic
    fun xof(seed: ByteArray, byte1: Byte, byte2: Byte): HashOutputStream =
        SHAKE128().apply {
            update(seed)
            update(byte1)
            update(byte2)
        }.stream()

    @JvmSynthetic
    fun prf(eta: Int, seed: ByteArray, byte: Byte): ByteArray =
        SHAKE256((KyberConstants.N shr 2) * eta).apply {
            update(seed)
            update(byte)
        }.digest()

    @JvmSynthetic
    fun nttMatrixToVectorDot(matrix: Array<Array<IntArray>>, vector: Array<IntArray>, isTransposed: Boolean = false): Array<IntArray> {
        val result = Array(vector.size) { IntArray(KyberConstants.N) }

        for(i in matrix.indices)
            for(j in vector.indices) {
                val a = if(isTransposed) j else i
                val b = if(isTransposed) i else j
                vectorToVectorAdd(result[i], multiplyNTTs(matrix[a][b], vector[j]))
            }

        return result
    }

    @JvmSynthetic
    fun vectorAddition(v1: Array<IntArray>, v2: Array<IntArray>){
        for(i in v1.indices) vectorToVectorAdd(v1[i], v2[i])
    }

    @JvmSynthetic
    fun vectorToVectorAdd(v1: IntArray, v2: IntArray) {
        for(i in v1.indices) v1[i] += v2[i]
    }

    @JvmSynthetic
    fun vectorToMontVector(vector: IntArray) {
        for(i in vector.indices) vector[i] = barrettReduce(toMontgomeryForm(vector[i]))
    }

    @JvmSynthetic
    fun barrettReduce(n: Int): Int {
        val q = (n * KyberConstants.BARRETT_APPROX) shr 26
        val result = n - (q * KyberConstants.Q)

        return if(result == KyberConstants.Q) 0 else result
    }

    /**
     * Partial Barrett Reduction to check if n is mod of Q.
     */
    @JvmSynthetic
    fun isModuloOfQ(n: Int): Boolean = ((n * KyberConstants.BARRETT_APPROX) shr 26) == 0 && n >= 0

    @JvmSynthetic
    fun montgomeryReduce(t: Int): Int {
        val m = (t * KyberConstants.Q_INV) and 0xFFFF//((KyberConstants.MONT_R shl 1) - 1) //mod MONT_R
        val u = (t + (m * KyberConstants.Q)) shr 16
        return u //Lazy Montgomery Reduction. This assumes that the final operation is a Barrett Reduction.
    }

    //Since a is ALWAYS a Short(16 bits) then it will always fit in Int(32 bits), and it will be modulo Q too.
    @JvmSynthetic
    fun toMontgomeryForm(a: Int): Int = montgomeryReduce(a * KyberConstants.MONT_R2)

    /**
     * From here on, these functions are used for testing or to generate constants.
     */

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

        for(i in 0 until e)
            c = (b * c) % m

        return c
    }

    @JvmSynthetic
    private fun pow(a: Int, b: Int): Long {
        var out = 1L

        for(i in 0 until b) {
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