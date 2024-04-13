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

import kotlin.test.Test
import kotlin.time.measureTime

//@Ignore //Comment
class Benchmark {

    @Test
    fun fullBenchmark() {
        val results = DoubleArray(9)

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
            "| 512     | " + results[0] + " |  " + results[1] + "  |  " + results[2] + "  |\n" +
            "| 768     | " + results[3] + " |  " + results[4] + "  |  " + results[5] + "  |\n" +
            "| 1024    | " + results[6] + " |  " + results[7] + "  |  " + results[8] + "  |\n" +
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
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
            for(i in 0..<10_000) {
                KyberAgreement.encapsulate(bob.encapsulationKey)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun encapsulation768(): Long {
        println("Benchmarking Encapsulation(10000) for 768...")

        val time = measureTime {
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)
            for(i in 0..<10_000) {
                KyberAgreement.encapsulate(bob.encapsulationKey)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")

        return time
    }

    fun encapsulation1024(): Long {
        println("Benchmarking Encapsulation(10000) for 1024...")

        val time = measureTime {
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)
            for(i in 0..<10_000) {
                KyberAgreement.encapsulate(bob.encapsulationKey)
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
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

            val result = KyberAgreement.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KyberAgreement(bob.decapsulationKey)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
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
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)

            val result = KyberAgreement.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KyberAgreement(bob.decapsulationKey)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
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
            val alice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)
            val bob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)

            val result = KyberAgreement.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KyberAgreement(bob.decapsulationKey)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
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