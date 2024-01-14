package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

class Benchmark {
    @Test
    fun generateKeys512() {
        println("Benchmarking Key Generation(10000) for 512...")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun generateKeys768() {
        println("Benchmarking Key Generation(10000) for 768...")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_768)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun generateKeys1024() {
        println("Benchmarking Key Generation(10000) for 1024")

        val time = measureTime {
            for(i in 0..<10_000) {
                KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_1024)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun encapsulation512() {
        println("Benchmarking Encapsulation(10000) for 512...")

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
            for(i in 0..<10_000) {
                val agreementAlice = KeyAgreement(alice)

                agreementAlice.encapsulate(bob.encapsulationKey)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun encapsulation768() {
        println("Benchmarking Encapsulation(10000) for 768...")

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_768)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_768)
            for(i in 0..<10_000) {
                val agreementAlice = KeyAgreement(alice)

                agreementAlice.encapsulate(bob.encapsulationKey)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun encapsulation1024() {
        println("Benchmarking Encapsulation(10000) for 1024...")

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_1024)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_1024)
            for(i in 0..<10_000) {
                val agreementAlice = KeyAgreement(alice)

                agreementAlice.encapsulate(bob.encapsulationKey)
            }
        }.inWholeMilliseconds

        println("Done after: " + time + "ms")
    }

    @Test
    fun decapsulation512() {
        println("Benchmarking Decapsulation(10000) for 512...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)

            val agreementAlice = KeyAgreement(alice)
            val result = agreementAlice.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KeyAgreement(bob)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")
    }

    @Test
    fun decapsulation768() {
        println("Benchmarking Decapsulation(10000) for 768...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_768)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_768)

            val agreementAlice = KeyAgreement(alice)
            val result = agreementAlice.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KeyAgreement(bob)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")
    }

    @Test
    fun decapsulation1024() {
        println("Benchmarking Decapsulation(10000) for 1024...")

        var success = 0
        var failure = 0

        val time = measureTime {
            val alice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_1024)
            val bob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_1024)

            val agreementAlice = KeyAgreement(alice)
            val result = agreementAlice.encapsulate(bob.encapsulationKey)
            for(i in 0..<10_000) {
                val agreementBob = KeyAgreement(bob)

                val secret = agreementBob.decapsulate(result.cipherText)

                if(result.secretKey.contentEquals(secret))
                    success++
                else
                    failure++
            }
        }.inWholeMilliseconds

        println("$failure / " + (success + failure) + " failures.")
        println("Done after: " + time + "ms")
    }
}