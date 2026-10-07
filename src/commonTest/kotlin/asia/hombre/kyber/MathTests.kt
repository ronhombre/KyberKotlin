/*
 * Copyright 2026 Ron Lauren Hombre
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
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Tests the KyberMath functions.
 *
 * @author Ron Lauren Hombre
 */
class MathTests {
    fun trueModulo(a: Int, b: Int): Int = ((a % b) + b) % b

    /**
     * Tests if the Barrett Reduction yields correct values.
     */
    @Test
    fun barrettApproximationVerification() {
        for (i in Short.MIN_VALUE .. Short.MAX_VALUE) {
            assertEquals(trueModulo(i, KyberConstants.Q), KyberMath.barrettReduce(i), "True Value: $i")
        }
    }

    /**
     * Tests if the Montgomery Reduction is reversible.
     */
    @Test
    fun montgomeryReturnVerification() {
        for (i in 0 ..Short.MAX_VALUE) {
            assertEquals(trueModulo(i, KyberConstants.Q), KyberMath.barrettReduce(KyberMath.montgomeryReduce(KyberMath.toMontgomeryForm(i))), "True Value: $i")
        }
    }

    /**
     * Tests the NTT and NTT^-1 functions (if they are reversible).
     */
    @Test
    fun nttVerification() {
        (0 until KyberConstants.Q).forEach { i ->
            val array = IntArray(256) {
                return@IntArray i
            }

            //We are barrett reducing here because barrett reduce is skipped in the function since it's not immediately needed
            val nttArray = KyberMath.ntt(array).also {
                it.forEachIndexed { i, value ->
                    it[i] = KyberMath.barrettReduce(value)
                }
            }
            val result = KyberMath.nttInv(nttArray).also {
                it.forEachIndexed { i, value ->
                    it[i] = KyberMath.barrettReduce(value)
                }
            }

            assertContentEquals(array, result, "NTT Failure!")
        }
    }

    /**
     * Tests if the `KyberMath.isModuloOfQ(n)` function correctly validates values -1<n<Q as `true`.
     */
    @Test
    fun moduloCheckPositive() {
        (0 until KyberConstants.Q).forEach { i ->
            assertTrue(KyberMath.isModuloOfQ(i), "Modulo Check Failed for $i!")
        }
    }

    /**
     * Tests if the `KyberMath.isModuloOfQ(n)` function correctly validates values (Q-1)<n<32767 as `false`.
     */
    @Test
    fun moduloCheckPositiveInvalid() {
        (KyberConstants.Q until Short.MAX_VALUE).forEach { i ->
            assertFalse(KyberMath.isModuloOfQ(i), "Modulo Check should fail for $i!")
        }
    }

    /**
     * Tests if the `KyberMath.isModuloOfQ(n)` function correctly validates values -(Q-1)<n<0 as `false`.
     */
    @Test
    fun moduloCheckNegative() {
        (-(KyberConstants.Q - 1) until 0).forEach { i ->
            assertFalse(KyberMath.isModuloOfQ(i), "Modulo Check should fail for $i!")
        }
    }

    /**
     * Tests if the `KyberMath.isModuloOfQ(n)` function correctly validates values -32768<n<-(Q-1) as `false`.
     */
    @Test
    fun moduloCheckNegativeInvalid() {
        (Short.MIN_VALUE until -(KyberConstants.Q - 1)).forEach { i ->
            assertFalse(KyberMath.isModuloOfQ(i), "Modulo Check should fail for $i!")
        }
    }
}