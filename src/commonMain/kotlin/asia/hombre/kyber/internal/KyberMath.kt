package asia.hombre.kyber.internal

import asia.hombre.kyber.KyberConstants
import org.kotlincrypto.endians.LittleEndian
import org.kotlincrypto.endians.LittleEndian.Companion.toLittleEndian
import org.kotlincrypto.hash.sha3.SHAKE128
import org.kotlincrypto.hash.sha3.SHAKE256
import kotlin.math.*

internal class KyberMath {
    companion object {
        val Boolean.int
            get() = (if (this) 1 else 0)

        val Boolean.uint
            get() = (if (this) 1u else 0u)

        fun bitsToBytes(bits: BooleanArray): ByteArray {
            val byteArray = ByteArray(ceil(bits.size / 8.0).toInt())

            for(i in bits.indices) {
                val bIndex = floor(i / 8.0).toInt()
                byteArray[bIndex] = (byteArray[bIndex].toInt() or (bits[i].int shl (i % 8))).toByte()
            }

            return byteArray
        }

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

        fun compress(shorts: ShortArray, bitSize: Int): ShortArray {
            val compressed = ShortArray(shorts.size)

            for(i in shorts.indices)
                compressed[i] = (((1 shl bitSize) * shorts[i]) / KyberConstants.Q.toDouble()).roundToInt().toShort()

            return compressed
        }

        fun decompress(shorts: ShortArray, bitSize: Int): ShortArray {
            val decompressed = ShortArray(shorts.size)

            for (i in shorts.indices)
                decompressed[i] = ((KyberConstants.Q * shorts[i]) / (1 shl bitSize).toDouble()).roundToInt().toShort()

            return decompressed
        }

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

        fun byteDecode(byteArray: ByteArray, bitSize: Int): ShortArray {
            val bits = bytesToBits(byteArray)
            val shorts = ShortArray(bits.size / bitSize)
            for(i in shorts.indices) {
                for(j in 0..<(bitSize)) {
                    val value = shorts[i].toInt() or (bits[(i * bitSize) + j].int shl j)
                    var mod = pow(2, bitSize + 1).toShort()

                    if((j + 1) == bitSize)
                        mod = KyberConstants.Q.toShort()

                    shorts[i] = moduloOf(value, mod)/*
                    if(value.toInt() != shorts[i].toInt())
                        println(value.toString() + " | " + shorts[i].toInt())*/
                }
            }

            return shorts
        }

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

        fun bytesToBitString(byteArray: ByteArray, bitCount: Int, joiner: String): String {
            var stringOutput = ""
            var count = 0
            for(byte in byteArray) {
                val bits = KyberMath.bytesToBits(byteArrayOf(byte))
                for(bit in bits) {
                    stringOutput += bit.int

                    count++

                    if(count >= bitCount) {
                        stringOutput += joiner
                        count = 0
                    }
                }
            }

            return stringOutput.removeSuffix(joiner).reversed()
        }

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
                f[i] = moduloOf(x - y, KyberConstants.Q)
            }

            return f
        }

        fun grabBit(x: Int, n: Int): Int {
            return (1 shl n) and x
        }

        fun reverseBits(x: Int): UByte {
            return (((1 and x) shl 6) or
                    (((1 shl 1) and x) shl 4) or
                    (((1 shl 2) and x) shl 2) or
                    (((1 shl 3) and x)) or
                    (((1 shl 4) and x) ushr 2) or
                    (((1 shl 5) and x) ushr 4) or
                    (((1 shl 6) and x) ushr 6)).toUByte()
        }

        fun montgomeryReduce(a: Int, b: Int, bInv: Int): Short {
            val t = (a * bInv).toShort()
            return ((a - (t * b)) ushr 16).toShort()
        }

        fun pow(a: Int, b: Int): Long {
            var out = 1L

            for(i in 0..<b) {
                out *= a
            }

            return out
        }

        //Functionally equivalent to pow_mod(b, e, mod) in Python, except values are kept positive
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

        //Modified Extended Euclidean Algorithm
        fun modMulInv(b: Int, e: Int, m: Int): Long {
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

        fun NTT(polynomials: ShortArray): ShortArray {
            val output = polynomials.copyOf()

            var k = 1
            var len = 128

            while(len >= 2) {
                for(start in 0..<256 step (2 * len)) {
                    for(j in start..<(start + len)) {
                        val t = ((KyberConstants.PRECOMPUTED_ZETAS_TABLE[k] * output[j + len]) % KyberConstants.Q)
                        output[j + len] = moduloOf(output[j] - t, KyberConstants.Q)
                        output[j] = moduloOf(output[j] + t, KyberConstants.Q)
                    }
                    k++
                }

                len = len shr 1
            }

            return output
        }

        fun invNTT(nttPolynomials: ShortArray): ShortArray {
            val output = nttPolynomials.copyOf()

            var k = 127
            var len = 2

            while(len <= 128) {
                for(start in 0..<256 step (2 * len)) {
                    for(j in start..<(start + len)) {
                        val t = output[j]
                        output[j] = ((t + output[j + len]) % KyberConstants.Q).toShort()
                        output[j + len] = ((KyberConstants.PRECOMPUTED_ZETAS_TABLE[k] * (output[j + len] - t)) % KyberConstants.Q).toShort()
                    }
                    k--
                }

                len = len shl 1
            }

            for(i in output.indices)
                output[i] = moduloOf(output[i].toInt() * 3303, KyberConstants.Q)

            return output
        }

        fun productOf(a: Short, b: Short): Short {
            return moduloOf(a.toInt() * b.toInt(), KyberConstants.Q)
        }

        fun sumOf(a: Short, b: Short): Short {
            return moduloOf(a.toInt() + b.toInt(), KyberConstants.Q)
        }

        fun diffOf(a: Short, b: Short): Short {
            return moduloOf(a.toInt() - b.toInt(), KyberConstants.Q)
        }

        fun multiplyNTTs(ntt1: ShortArray, ntt2: ShortArray): ShortArray {
            val multipliedNtt = ShortArray(256)

            for(i in 0..<128) {
                val first = 2 * i
                val second = first + 1
                multipliedNtt[first] = sumOf(productOf(ntt1[first], ntt2[first]), productOf(productOf(ntt1[second], ntt2[second]), KyberConstants.PRECOMPUTED_GAMMAS_TABLE[i]))
                multipliedNtt[second] = sumOf(productOf(ntt1[first], ntt2[second]), productOf(ntt1[second], ntt2[first]))
            }

            return multipliedNtt
        }

        fun xof(seed: ByteArray, byte1: Byte, byte2: Byte): ByteArray {
            val shake128 = SHAKE128(672)

            shake128.update(seed)
            shake128.update(byte1)
            shake128.update(byte2)

            return shake128.digest()
        }

        fun prf(eta: Int, seed: ByteArray, byte: Byte): ByteArray {
            var shake256 = SHAKE256(64 * eta)

            shake256.update(seed)
            shake256.update(byte)

            return shake256.digest()
        }

        fun nttMatrixMultiply(m: Array<Array<ShortArray>>, v: Array<ShortArray>): Array<ShortArray> { //TODO: Transpose option
            val result = Array(v.size) { ShortArray(v[0].size)}
            for(i in m.indices) {
                if(m[i].size != v.size)
                    throw ArithmeticException("Matrix column count does not match Vector row count!")
                for(j in v.indices) {
                    if(m[i][j].size != v[j].size)
                        throw ArithmeticException("No match!") //TODO: Fix
                    result[j] = multiplyNTTs(m[i][j], v[j])
                }
            }

            return result
        }

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

        fun vectorAddition(v1: Array<ShortArray>, v2: Array<ShortArray>): Array<ShortArray> {
            val result = Array(v1.size) { ShortArray(v2[0].size) }

            for(i in v1.indices)
                result[i] = vectorToVectorAdd(v1[i], v2[i])

            return result
        }

        fun vectorToVectorAdd(v1: ShortArray, v2: ShortArray): ShortArray {
            val result = ShortArray(v1.size)

            for(i in v1.indices)
                result[i] = sumOf(v1[i], v2[i])

            return result
        }

        fun transposeMatrix(matrix: Array<Array<ShortArray>>): Array<Array<ShortArray>> {
            val matrixT = Array(matrix[0].size) { Array(matrix.size) { ShortArray(matrix[0][0].size) } }

            for(j in matrix[0].indices)
                for(i in matrix.indices)
                    matrixT[j][i] = matrix[i][j]

            return matrixT
        }

        fun moduloOf(value: Number, modulo: Number): Short {
            val shortedValue = value.toInt()
            val shortedModulo = modulo.toShort()
            return if(shortedValue < 0) (shortedModulo - (abs(shortedValue) % shortedModulo)).toShort()
            else (shortedValue % shortedModulo).toShort()
        }
    }
}