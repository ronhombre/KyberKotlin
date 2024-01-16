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

import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.min
import kotlin.random.Random
import kotlin.random.nextULong
import kotlin.time.measureTime

/*
* This class is NOT AN APPROVED CSPRNG Secure Random Generator. Although it relies on the innate randomness of execution
* times, as any given instruction runs differently each time to a certain point. By multiplying it with large and
* variable prime integers, we can make a good random number. Then we can seed Kotlin's built-in Random() function and
* XOR the output. Since XOR is a lossy process, it would be impossible to recover the initial values. However, the
* resistance of this class from Timing Attacks is unknown. Use it with caution.
 */
internal class SecureRandom {
    companion object {
        fun generateSecureBytes(range: Int): ByteArray {
            val count = ceil(range.toDouble() / 8).toInt()
            val bytes = ByteArray(range)

            for(i in 0..<count) {
                generateSecureBytes().copyInto(bytes, i * 8, 0, min(8, range - ((i + 1) * 8) + 8))
            }

            return bytes
        }

        private fun generateSecureBytes(): ByteArray {
            val secureLong = generateULong() xor Random(generateULong().toLong()).nextULong()

            return uLongToByteArray(secureLong)
        }

        @OptIn(ExperimentalUnsignedTypes::class)
        private fun generateULong(): ULong {
            var minimum = ULong.MAX_VALUE
            val nanoTimes = ULongArray(7)
            var previous = 256

            for(i in nanoTimes.indices) {
                val d = measureTime {
                    countPrimes(previous)
                }
                nanoTimes[i] = d.inWholeNanoseconds.toULong()
                minimum = min(d.inWholeNanoseconds.toULong(), minimum) //Remove the non-random minimum execution time.
                previous += d.inWholeMicroseconds.toInt() / 2
            }

            var randomLong = 1uL

            val randomPrimes =  arrayOf(998_244_353uL, 1_151uL, 999_999_733uL, 1_291uL, 49_999_819uL, 3uL, 997_369uL)

            for(i in nanoTimes.indices) {
                val multiplicative = nanoTimes[i] - (minimum / 2u) + randomPrimes[i]
                randomLong *= multiplicative
            }

            return randomLong
        }

        private fun uLongToByteArray(uLong: ULong): ByteArray {
            val bytes = ByteArray(ULong.SIZE_BYTES)

            for(i in bytes.indices) {
                bytes[i] = (uLong shr (8 * i)).toByte()
            }

            return bytes
        }

        private fun countPrimes(upTo: Int): Int {
            var counter = 1 //Include 2
            var randomizer = 1 //Mess up the branch prediction

            for(i in (3).rangeTo(upTo) step 2) {
                counter++
                for(j in (3)..<i) {
                    val test: Double = i.toDouble() / j.toDouble()
                    if((test - floor(test)) == 0.0) {
                        counter--
                        break
                    }
                    /**
                     * Although Random is not a CSPRNG, it brings in enough "randomness" to mess up the branch prediction.
                     * This grabs the innate randomness of branch prediction and adds to the time of running countPrimes().
                     * Randomness over Speed
                     */
                    if(test.toInt() % (Random.nextInt(4) + 1) == 0)
                        randomizer++
                }
            }

            return counter
        }
    }
}