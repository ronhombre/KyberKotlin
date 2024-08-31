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

package asia.hombre.kyber.tests

import asia.hombre.kyber.*
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

//@Ignore //Remove
class JVMBenchmark {
    @Test
    fun fullBenchmark() {
        val results = DoubleArray(9)
        val comparingResults = doubleArrayOf(8333.0, 8938.0, 9936.0, 13553.0, 15049.0, 16884.0, 21255.0, 23226.0, 26006.0)

        for(i in 0..<5) {
            results[0] += generateKeys512().toDouble()
            if(i > 0)
                results[0] /= 2.0
        }

        for(i in 0..<5) {
            results[1] += encapsulation512().toDouble()
            if(i > 0)
                results[1] /= 2.0
        }

        for(i in 0..<5) {
            results[2] += decapsulation512().toDouble()
            if(i > 0)
                results[2] /= 2.0
        }

        for(i in 0..<5) {
            results[3] += generateKeys768().toDouble()
            if(i > 0)
                results[3] /= 2.0
        }

        for(i in 0..<5) {
            results[4] += encapsulation768().toDouble()
            if(i > 0)
                results[4] /= 2.0
        }

        for(i in 0..<5) {
            results[5] += decapsulation768().toDouble()
            if(i > 0)
                results[5] /= 2.0
        }

        for(i in 0..<5) {
            results[6] += generateKeys1024().toDouble()
            if(i > 0)
                results[6] /= 2.0
        }

        for(i in 0..<5) {
            results[7] += encapsulation1024().toDouble()
            if(i > 0)
                results[7] /= 2.0
        }

        for(i in 0..<5) {
            results[8] += decapsulation1024().toDouble()
            if(i > 0)
                results[8] /= 2.0
        }

        val finalResult =
            "| Variant | Generation | Encapsulation | Decapsulation |\n" +
                    "|---------|------------|---------------|---------------|\n" +
                    "| 512     | " + results[0] + "(" + (comparingResults[0] / results[0]) + "% Faster) |  " + results[1] + "(" + (comparingResults[1] / results[1]) + "% Faster)  |  " + results[2] + "(" + (comparingResults[2] / results[2]) + "% Faster)  |\n" +
                    "| 768     | " + results[3] + "(" + (comparingResults[3] / results[3]) + "% Faster) |  " + results[4] + "(" + (comparingResults[4] / results[4]) + "% Faster)  |  " + results[5] + "(" + (comparingResults[5] / results[5]) + "% Faster)  |\n" +
                    "| 1024    | " + results[6] + "(" + (comparingResults[6] / results[6]) + "% Faster) |  " + results[7] + "(" + (comparingResults[7] / results[7]) + "% Faster)  |  " + results[8] + "(" + (comparingResults[8] / results[8]) + "% Faster)  |\n" +
                    "| ML-KEM  | (in ms)    | (in ms)       | (in ms)       |"

        println(finalResult)
    }

    fun generateKeys512(): Long {
        println("Benchmarking Key Generation(10000) for 512...")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun generateKeys768(): Long {
        println("Benchmarking Key Generation(10000) for 768...")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun generateKeys1024(): Long {
        println("Benchmarking Key Generation(10000) for 1024")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun encapsulation512(): Long {
        println("Benchmarking Encapsulation(10000) for 512...")

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
            for(i in 0..<10_000) {
                bob.encapsulationKey.encapsulate()
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun encapsulation768(): Long {
        println("Benchmarking Encapsulation(10000) for 768...")

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)
            for(i in 0..<10_000) {
                bob.encapsulationKey.encapsulate()
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun encapsulation1024(): Long {
        println("Benchmarking Encapsulation(10000) for 1024...")

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)
            for(i in 0..<10_000) {
                bob.encapsulationKey.encapsulate()
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun decapsulation512(): Long {
        println("Benchmarking Decapsulation(10000) for 512...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

            val result = bob.encapsulationKey.encapsulate()
            for(i in 0..<10_000) {
                val secret = result.cipherText.decapsulate(bob.decapsulationKey)

                if(result.sharedSecretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")

        return time
    }

    fun decapsulation768(): Long {
        println("Benchmarking Decapsulation(10000) for 768...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)

            val result = bob.encapsulationKey.encapsulate()
            for(i in 0..<10_000) {
                val secret = result.cipherText.decapsulate(bob.decapsulationKey)

                if(result.sharedSecretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")

        return time
    }

    fun decapsulation1024(): Long {
        println("Benchmarking Decapsulation(10000) for 1024...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)

            val result = bob.encapsulationKey.encapsulate()
            for(i in 0..<10_000) {
                val secret = result.cipherText.decapsulate(bob.decapsulationKey)

                if(result.sharedSecretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")

        return time
    }
}