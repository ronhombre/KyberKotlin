package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.KyberMath.Companion.int
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

//@Ignore
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
    fun generateZetas() {
        println("Generating Zetas...")

        val time = measureTime {
            val zetas = ShortArray(128)
            zetas[0] = 1
            for(i in 1..<128) {
                zetas[i] = KyberMath.powMod(17, KyberMath.reverseBits(i).toInt(), KyberConstants.Q).toShort()
            }

            println("{" + zetas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @Test
    fun generateGammas() {
        println("Generating Gammas...")

        val time = measureTime {
            val gammas = ShortArray(128)
            for(i in 1..128) {
                gammas[i - 1] = KyberMath.powMod(17, (2 * KyberMath.reverseBits(i - 1).toInt()) + 1, KyberConstants.Q).toShort()
            }

            println("{" + gammas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    private fun verifyPrecomputed(x: ShortArray, xIndex: Int, y: ShortArray, yIndex: Int): Boolean {
        return x[xIndex] == y[yIndex]
    }
}