package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.KyberMath.Companion.int
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

@Ignore
class Generators {
    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun generateInverseExpTable() {
        println("Generating InverseExpTable...")
        val time = measureTime {
            val table = UByteArray(128)
            for(i in 0..<128) {
                table[i] = KyberMath.reverseBits(i)
            }

            println("{" + table.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun generateNTTTable() {
        println("Generating NTTTable...")

        val time = measureTime {
            val inverseExp = UByteArray(128)
            for(i in 0..<128) {
                inverseExp[i] = KyberMath.reverseBits(i)
            }

            val rawMont = (1 shl 16) % KyberConstants.Q
            val preMont = ((rawMont * 17) % KyberConstants.Q).toShort()

            val qInv = KyberMath.powMod(KyberConstants.Q, -1, 1 shl 16).toInt()

            val zetas = ShortArray(128)
            for(i in 1..128) {
                zetas[i - 1] = KyberMath.powMod(17, (2 * KyberMath.reverseBits(i - 1).toInt()) + 1, KyberConstants.Q).toShort()
            }

            println("{" + zetas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun verifyPrecomputed(x: ShortArray, xIndex: Int, y: ShortArray, yIndex: Int): Boolean {
        return x[xIndex] == y[yIndex]
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

        return stringOutput.removeSuffix(joiner)
    }
}