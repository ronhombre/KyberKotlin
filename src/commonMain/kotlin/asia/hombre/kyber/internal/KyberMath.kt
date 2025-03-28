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

import asia.hombre.keccak.KeccakByteStream
import asia.hombre.keccak.KeccakHash
import asia.hombre.keccak.KeccakParameter
import asia.hombre.kyber.KyberConstants
import kotlin.jvm.JvmSynthetic
import kotlin.math.absoluteValue

internal object KyberMath {
    @get:JvmSynthetic
    val Boolean.int
        get() = this.compareTo(false)

    @JvmSynthetic
    fun bitsToBytes(bits: BooleanArray): ByteArray {
        val byteArray = ByteArray(bits.size shr 3)

        for(i in byteArray.indices) {
            byteArray[i] = (bits[(i * 8)].int or
                    (bits[(i * 8) + 1].int shl 1) or
                    (bits[(i * 8) + 2].int shl 2) or
                    (bits[(i * 8) + 3].int shl 3) or
                    (bits[(i * 8) + 4].int shl 4) or
                    (bits[(i * 8) + 5].int shl 5) or
                    (bits[(i * 8) + 6].int shl 6) or
                    (bits[(i * 8) + 7].int shl 7)).toByte()
        }

        return byteArray
    }

    @JvmSynthetic
    fun bytesToBits(bytes: ByteArray): BooleanArray {
        val bitArray = BooleanArray(bytes.size * 8)

        for(i in bytes.indices) {
            val byte = bytes[i].toUByte().toInt() //Preserve leftmost bit
            bitArray[(8 * i)] = (byte and 0b1) == 1
            bitArray[(8 * i) + 1] = ((byte shr 1) and 0b1) == 1
            bitArray[(8 * i) + 2] = ((byte shr 2) and 0b1) == 1
            bitArray[(8 * i) + 3] = ((byte shr 3) and 0b1) == 1
            bitArray[(8 * i) + 4] = ((byte shr 4) and 0b1) == 1
            bitArray[(8 * i) + 5] = ((byte shr 5) and 0b1) == 1
            bitArray[(8 * i) + 6] = ((byte shr 6) and 0b1) == 1
            bitArray[(8 * i) + 7] = ((byte shr 7) and 0b1) == 1
        }

        return bitArray
    }

    @JvmSynthetic
    fun compress(shorts: IntArray, bitSize: Int): IntArray {
        val compressed = IntArray(shorts.size)

        for(i in shorts.indices)
            compressed[i] = (((1 shl bitSize) * shorts[i]) + KyberConstants.Q_HALF) / KyberConstants.Q

        return compressed
    }

    @JvmSynthetic
    fun decompress(shorts: IntArray, bitSize: Int): IntArray {
        val decompressed = IntArray(shorts.size)

        for (i in shorts.indices)
            decompressed[i] = ((KyberConstants.Q * shorts[i]) + (1 shl (bitSize - 1))) / (1 shl bitSize)

        return decompressed
    }

    @JvmSynthetic
    fun singleDecompress(shorts: IntArray): IntArray {
        val decompressed = IntArray(shorts.size)
        val decompressConstant = KyberConstants.Q_HALF

        for (i in shorts.indices)
            decompressed[i] = toMontgomeryForm(shorts[i] * decompressConstant)

        return decompressed
    }

    @JvmSynthetic
    fun byteEncode(shorts: IntArray, bitSize: Int): ByteArray {
        if(bitSize > UShort.SIZE_BITS)
            throw ArithmeticException("There are not enough bits to encode! Bit Size: $bitSize is too big!")

        val bits = BooleanArray(shorts.size * bitSize)

        for(i in shorts.indices)
            for(j in 0..<bitSize)
                bits[(i * bitSize) + j] = ((barrettReduce(shorts[i]) shr j) and 1) == 1

        return bitsToBytes(bits)
    }

    @JvmSynthetic
    fun byteDecode(byteArray: ByteArray, bitSize: Int): IntArray {
        val bits = bytesToBits(byteArray)
        val shorts = IntArray(bits.size / bitSize)
        for(i in shorts.indices)
            for(j in 0..<(bitSize))
                shorts[i] = shorts[i] + (bits[(i * bitSize) + j].int shl j)

        return shorts
    }

    @JvmSynthetic
    fun singleByteDecode(byteArray: ByteArray): IntArray {
        val bits = bytesToBits(byteArray)
        val shorts = IntArray(bits.size)
        for(i in shorts.indices)
            shorts[i] = bits[i].int

        return shorts
    }

    @JvmSynthetic
    fun sampleNTT(byteStream: KeccakByteStream): IntArray {
        val nttCoefficients = IntArray(KyberConstants.N)

        val buffer = ByteArray(3)

        var j = 0
        while(j < KyberConstants.N) {
            //Fill byte buffer
            buffer[0] = byteStream.next()
            buffer[1] = byteStream.next()
            buffer[2] = byteStream.next()

            val d1 = ((buffer[0].toInt() and 0xFF) or ((buffer[1].toInt() and 0xFF) shl 8) and 0xFFF)
            val d2 = ((buffer[1].toInt() and 0xFF) shr 4 or ((buffer[2].toInt() and 0xFF) shl 4) and 0xFFF)

            if(d1 < KyberConstants.Q) {
                nttCoefficients[j] = toMontgomeryForm(d1)
                j++
            }
            if(d2 < KyberConstants.Q && j < KyberConstants.N) {
                nttCoefficients[j] = toMontgomeryForm(d2)
                j++
            }
        }

        return nttCoefficients
    }

    @JvmSynthetic
    fun samplePolyCBD(eta: Int, bytes: ByteArray): IntArray {
        val f = IntArray(KyberConstants.N)
        val bits = bytesToBits(bytes)

        bytes.fill(0, 0, bytes.size) //Security Feature

        for(i in 0..<KyberConstants.N) {
            var x = 0
            var y = 0
            for(j in 0..<eta) {
                x += bits[(2 * i * eta) + j].int
                y += bits[(2 * i * eta) + eta + j].int
            }
            f[i] = toMontgomeryForm(x - y)
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
    fun ntt(polynomials: IntArray): IntArray {
        val output = polynomials.copyOf()

        var k = 1
        var len = KyberConstants.N shr 1

        while(len >= 2) {
            for(start in 0..<KyberConstants.N step (2 * len)) {
                for(j in start..<(start + len)) {
                    val temp = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], output[j + len])
                    output[j + len] = barrettReduce(output[j] - temp)
                    output[j] = output[j] + temp //Turns out you don't need to Barrett Reduce this.
                }
                k++
            }

            len = len shr 1
        }

        //However, to guarantee modulo Q, this has to be done at the end.
        for(i in output.indices)
            output[i] = barrettReduce(output[i])

        return output
    }

    @JvmSynthetic
    fun nttInv(nttPolynomials: IntArray): IntArray {
        val output = nttPolynomials.copyOf()

        var k = (KyberConstants.N shr 1) - 1
        var len = 2

        while(len <= (KyberConstants.N shr 1)) {
            for(start in 0..<KyberConstants.N step (2 * len)) {
                for(j in start..<(start + len)) {
                    val temp = output[j]
                    output[j] = temp + output[j + len] //Turns out you don't need to Barrett Reduce this.
                    output[j + len] = productOf(KyberConstants.PRECOMPUTED_ZETAS_TABLE[k], barrettReduce(output[j + len] - temp))
                }
                k--
            }

            len = len shl 1
        }

        for(i in output.indices)
            output[i] = barrettReduce(productOf(output[i], 512)) // toMontgomeryForm(3303) = 512

        return output
    }

    @JvmSynthetic
    fun productOf(a: Int, b: Int): Int {
        return montgomeryReduce(a * b)
    }

    @JvmSynthetic
    fun multiplyNTTs(ntt1: IntArray, ntt2: IntArray): IntArray {
        val multipliedNtt = IntArray(KyberConstants.N)

        for(i in 0..<(KyberConstants.N shr 1)) {
            //Karatsuba Multiplication from 5 multiplication operations to 4 which also helps with reducing Montgomery Reductions.
            val x = productOf(ntt1[2 * i], ntt2[2 * i])
            val y = productOf(ntt1[(2 * i) + 1], ntt2[(2 * i) + 1])
            multipliedNtt[2 * i] = barrettReduce(
                x + productOf(y, KyberConstants.PRECOMPUTED_GAMMAS_TABLE[i])
            )
            multipliedNtt[(2 * i) + 1] = barrettReduce(
                productOf(ntt1[2 * i] + ntt1[(2 * i) + 1], ntt2[2 * i] + ntt2[(2 * i) + 1])
                        - x - y
            )
        }

        return multipliedNtt
    }

    @JvmSynthetic
    fun xof(seed: ByteArray, byte1: Byte, byte2: Byte): KeccakByteStream {
        val keccakStream = KeccakByteStream(KeccakParameter.SHAKE_128)

        keccakStream.absorb(seed)
        keccakStream.absorb(byte1)
        keccakStream.absorb(byte2)

        return keccakStream
    }

    @JvmSynthetic
    fun prf(eta: Int, seed: ByteArray, byte: Byte): ByteArray {
        val shakeBytes = ByteArray(seed.size + 1)

        seed.copyInto(shakeBytes)

        shakeBytes[shakeBytes.lastIndex] = byte

        return KeccakHash.generate(KeccakParameter.SHAKE_256, shakeBytes, (KyberConstants.N shr 2) * eta)
    }

    @JvmSynthetic
    fun nttMatrixToVectorDot(matrix: Array<Array<IntArray>>, vector: Array<IntArray>, isTransposed: Boolean = false): Array<IntArray> {
        val result = Array(vector.size) { IntArray(KyberConstants.N) }

        for(i in matrix.indices)
            for(j in vector.indices) {
                val a = if(isTransposed) j else i
                val b = if(isTransposed) i else j
                result[i] = vectorToVectorAdd(result[i], multiplyNTTs(matrix[a][b], vector[j]))
            }

        return result
    }

    @JvmSynthetic
    fun vectorAddition(v1: Array<IntArray>, v2: Array<IntArray>): Array<IntArray> {
        val result = Array(v1.size) { IntArray(v2[0].size) }

        for(i in v1.indices)
            result[i] = vectorToVectorAdd(v1[i], v2[i])

        return result
    }

    @JvmSynthetic
    fun vectorToVectorAdd(v1: IntArray, v2: IntArray): IntArray {
        val result = IntArray(v1.size)

        for(i in v1.indices)
            result[i] = v1[i] + v2[i]

        return result
    }

    @JvmSynthetic
    fun montVectorToVector(v1: IntArray): IntArray {
        val result = IntArray(v1.size)

        for(i in v1.indices)
            result[i] = montgomeryReduce(v1[i])

        return result
    }

    @JvmSynthetic
    fun vectorToMontVector(v1: IntArray): IntArray {
        val result = IntArray(v1.size)

        for(i in v1.indices)
            result[i] = toMontgomeryForm(v1[i])

        return result
    }

    @JvmSynthetic
    fun barrettReduce(n: Int): Int {
        val q = (n * KyberConstants.BARRETT_APPROX) shr 26

        return n - (q * KyberConstants.Q)
    }

    /**
     * Partial Barrett Reduction to check if n is mod of Q.
     */
    @JvmSynthetic
    fun isModuloOfQ(n: Int): Boolean {
        return ((n * KyberConstants.BARRETT_APPROX) shr 26) == 0
    }

    @JvmSynthetic
    fun montgomeryReduce(t: Int): Int {
        val m = (t * KyberConstants.Q_INV) and 0xFFFF//((KyberConstants.MONT_R shl 1) - 1) //mod MONT_R
        val u = (t + (m * KyberConstants.Q)) shr 16
        return u //Lazy Montgomery Reduction. This assumes that the final operation is a Barrett Reduction.
    }

    @JvmSynthetic
    fun toMontgomeryForm(a: Int): Int {
        //Since a is ALWAYS a Short(16 bits) then it will always fit in Int(32 bits), and it will be modulo Q too.
        return montgomeryReduce(a * KyberConstants.MONT_R2)
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