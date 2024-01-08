package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
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

            val tmp = ShortArray(128)
            tmp[0] = 2285
            for(i in 1..<128) {
                tmp[i] = KyberMath.montgomeryReduce((tmp[i - 1].toInt() * preMont), KyberConstants.Q, qInv)
            }

            val zetas = ShortArray(128)
            for(i in 0..<128) {
                var zeta = tmp[inverseExp[i].toInt()]

                if(zeta < 0)
                    zeta = (zeta + KyberConstants.Q).toShort()

                zetas[i] = zeta

                if(!verifyPrecomputed(KyberConstants.PRECOMPUTED_ZETAS_TABLE, i, zetas, i))
                    println("Wrong value at: $i")
            }

            println("{" + zetas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun verifyPrecomputed(x: ShortArray, xIndex: Int, y: ShortArray, yIndex: Int): Boolean {
        return x[xIndex] == y[yIndex]
    }
}