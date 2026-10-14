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

package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import kotlin.jvm.JvmSynthetic
import kotlin.math.absoluteValue
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

@Ignore //Comment
class Generators {
    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun generateInverseExpTable() {
        println("Generating InverseExpTable...")
        val time = measureTime {
            val table = UByteArray(128)
            for(i in 0..<128) {
                table[i] = reverseBits(i)
            }

            println("{" + table.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @Test
    fun generateZetas() {
        println("Generating Zetas...")

        val time = measureTime {
            val zetas = IntArray(128)
            zetas[0] = KyberMath.toMontgomeryForm(1)
            for(i in 1..<128) {
                zetas[i] = powMod(17, reverseBits(i).toInt(), KyberConstants.Q).toInt()
                zetas[i] = KyberMath.toMontgomeryForm(zetas[i]) //Comment this line if you want the standard form.
            }

            println("{" + zetas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @Test
    fun generateGammas() {
        println("Generating Gammas...")

        val time = measureTime {
            val gammas = IntArray(128)
            for(i in 1..128) {
                gammas[i - 1] = powMod(17, (2 * reverseBits(i - 1).toInt()) + 1, KyberConstants.Q).toInt()
                gammas[i - 1] = KyberMath.toMontgomeryForm(gammas[i - 1]) //Comment this line if you want the standard form.
            }

            println("{" + gammas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    @Suppress("unused")
    private fun verifyPrecomputed(x: IntArray, xIndex: Int, y: IntArray, yIndex: Int): Boolean {
        return x[xIndex] == y[yIndex]
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

    //Functionally equivalent to pow_mod(b, e, mod) in Python, except values are kept positive
    @JvmSynthetic
    fun powMod(b: Int, e: Int, m: Int): Long {
        if(e == 0) //b^0 = 1
            return 1L
        else if(e < 0) //Inverse
            return modMulInv(b, e.absoluteValue, m)

        var c = 1L

        (0 until e).forEach { _ ->
            c = (b * c) % m
        }

        return c
    }

    @JvmSynthetic
    private fun pow(a: Int, b: Int): Long {
        var out = 1L

        (0 until b).forEach { _ ->
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
}