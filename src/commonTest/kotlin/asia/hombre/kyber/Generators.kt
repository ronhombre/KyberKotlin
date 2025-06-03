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
            val zetas = IntArray(128)
            zetas[0] = KyberMath.toMontgomeryForm(1)
            for(i in 1..<128) {
                zetas[i] = KyberMath.powMod(17, KyberMath.reverseBits(i).toInt(), KyberConstants.Q).toInt()
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
                gammas[i - 1] = KyberMath.powMod(17, (2 * KyberMath.reverseBits(i - 1).toInt()) + 1, KyberConstants.Q).toInt()
                gammas[i - 1] = KyberMath.toMontgomeryForm(gammas[i - 1]) //Comment this line if you want the standard form.
            }

            println("{" + gammas.joinToString(", ") + "}")
        }.inWholeMilliseconds

        println("Generated after: " + time + "ms")
    }

    private fun verifyPrecomputed(x: IntArray, xIndex: Int, y: IntArray, yIndex: Int): Boolean {
        return x[xIndex] == y[yIndex]
    }
}