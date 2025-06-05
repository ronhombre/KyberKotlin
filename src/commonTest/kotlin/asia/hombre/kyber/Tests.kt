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

import asia.hombre.kyber.internal.KyberAgreement
import asia.hombre.kyber.internal.KyberMath
import org.kotlincrypto.random.CryptoRand
import kotlin.jvm.JvmSynthetic
import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class Tests {
    @get:JvmSynthetic
    val Boolean.int
        get() = this.compareTo(false)

    @Test
    fun playground() {

    }

    fun trueModulo(a: Int, b: Int): Int = ((a % b) + b) % b

    @Test
    fun barrettApproximationVerification() {
        for (i in Short.MIN_VALUE .. Short.MAX_VALUE) {
            assertEquals(trueModulo(i, KyberConstants.Q), KyberMath.barrettReduce(i), "True Value: $i")
        }
    }

    @Test
    fun montgomeryReturnVerification() {
        for (i in 0 ..Short.MAX_VALUE) {
            assertEquals(trueModulo(i, KyberConstants.Q), KyberMath.montgomeryReduce(KyberMath.toMontgomeryForm(i)), "True Value: $i")
        }
    }

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


    @Test
    fun bytesTest512() {
        val originalKeyPair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

        val bytesEncapsKey = originalKeyPair.encapsulationKey.fullBytes
        val bytesDecapsKey = originalKeyPair.decapsulationKey.fullBytes

        val recoveredKeyPair = KyberKEMKeyPair(KyberEncapsulationKey.fromBytes(bytesEncapsKey), KyberDecapsulationKey.fromBytes(bytesDecapsKey))

        assertContentEquals(originalKeyPair.encapsulationKey.key.fullBytes, recoveredKeyPair.encapsulationKey.key.fullBytes)
        assertContentEquals(originalKeyPair.decapsulationKey.fullBytes, recoveredKeyPair.decapsulationKey.fullBytes)

        val cipherText = originalKeyPair.encapsulationKey.encapsulate().cipherText

        val bytesCipherText = cipherText.fullBytes

        assertContentEquals(cipherText.fullBytes, KyberCipherText.fromBytes(bytesCipherText).fullBytes)
    }

    @Test
    fun bytesTest768() {
        val originalKeyPair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)

        val bytesEncapsKey = originalKeyPair.encapsulationKey.fullBytes
        val bytesDecapsKey = originalKeyPair.decapsulationKey.fullBytes

        val recoveredKeyPair = KyberKEMKeyPair(KyberEncapsulationKey.fromBytes(bytesEncapsKey), KyberDecapsulationKey.fromBytes(bytesDecapsKey))

        assertContentEquals(originalKeyPair.encapsulationKey.key.fullBytes, recoveredKeyPair.encapsulationKey.key.fullBytes)
        assertContentEquals(originalKeyPair.decapsulationKey.fullBytes, recoveredKeyPair.decapsulationKey.fullBytes)

        val cipherText = originalKeyPair.encapsulationKey.encapsulate().cipherText

        val bytesCipherText = cipherText.fullBytes

        assertContentEquals(cipherText.fullBytes, KyberCipherText.fromBytes(bytesCipherText).fullBytes)
    }

    @Test
    fun bytesTest1024() {
        val originalKeyPair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)

        val bytesEncapsKey = originalKeyPair.encapsulationKey.fullBytes
        val bytesDecapsKey = originalKeyPair.decapsulationKey.fullBytes

        val recoveredKeyPair = KyberKEMKeyPair(KyberEncapsulationKey.fromBytes(bytesEncapsKey), KyberDecapsulationKey.fromBytes(bytesDecapsKey))

        assertContentEquals(originalKeyPair.encapsulationKey.key.fullBytes, recoveredKeyPair.encapsulationKey.key.fullBytes)
        assertContentEquals(originalKeyPair.decapsulationKey.fullBytes, recoveredKeyPair.decapsulationKey.fullBytes)

        val cipherText = originalKeyPair.encapsulationKey.encapsulate().cipherText

        val bytesCipherText = cipherText.fullBytes

        assertContentEquals(cipherText.fullBytes, KyberCipherText.fromBytes(bytesCipherText).fullBytes)
    }

    @Test
    fun pkeEncryptDecrypt512() {
        for(i in 1..10000) {
            val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

            val original = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
            val cipher = KyberAgreement.encapsulate(keyPairBob.encapsulationKey, original.copyOf()).cipherText
            val recovered = KyberAgreement.fromCipherText(keyPairBob.decapsulationKey.key, cipher)

            assertContentEquals(original, recovered, "PKE Encryption and Decryption for 512 failed at attempt $i!")
        }
    }

    @Test
    fun pkeEncryptDecrypt768() {
        for(i in 1..10000) {
            val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)

            val original = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
            val cipher = KyberAgreement.encapsulate(keyPairBob.encapsulationKey, original.copyOf()).cipherText
            val recovered = KyberAgreement.fromCipherText(keyPairBob.decapsulationKey.key, cipher)

            assertContentEquals(original, recovered, "PKE Encryption and Decryption for 768 failed at attempt $i!")
        }
    }

    @Test
    fun pkeEncryptDecrypt1024() {
        for(i in 1..10000) {
            val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)

            val original = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
            val cipher = KyberAgreement.encapsulate(keyPairBob.encapsulationKey, original.copyOf()).cipherText
            val recovered = KyberAgreement.fromCipherText(keyPairBob.decapsulationKey.key, cipher)

            assertContentEquals(original, recovered, "PKE Encryption and Decryption for 1024 failed at attempt $i!")
        }
    }

    @Test
    fun mlEncapsDecaps512() {
        for(i in 1..10000) {
            val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

            val result = keyPairAlice.encapsulationKey.encapsulate()

            val bobSecretKey = result.sharedSecretKey
            val aliceSecretKey = result.cipherText.decapsulate(keyPairAlice.decapsulationKey)

            assertContentEquals(bobSecretKey, aliceSecretKey, "ML Encapsulation and Decapsulation for 512 failed at attempt $i!")
        }
    }

    @Test
    fun mlEncapsDecaps768() {
        for(i in 1..10000) {
            val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768)

            val result = keyPairAlice.encapsulationKey.encapsulate()

            val bobSecretKey = result.sharedSecretKey
            val aliceSecretKey = result.cipherText.decapsulate(keyPairAlice.decapsulationKey)

            assertContentEquals(bobSecretKey, aliceSecretKey, "ML Encapsulation and Decapsulation for 512 failed at attempt $i!")
        }
    }

    @Test
    fun mlEncapsDecaps1024() {
        for(i in 1..10000) {
            val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024)

            val result = keyPairAlice.encapsulationKey.encapsulate()

            val bobSecretKey = result.sharedSecretKey
            val aliceSecretKey = result.cipherText.decapsulate(keyPairAlice.decapsulationKey)

            assertContentEquals(bobSecretKey, aliceSecretKey, "ML Encapsulation and Decapsulation for 512 failed at attempt $i!")
        }
    }

    @Test
    fun regenerationComparison512() {
        val randomSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
        val pkeSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }

        val firstGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512, randomSeed, pkeSeed.copyOf())
        val secondGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512, randomSeed, pkeSeed.copyOf())

        assertContentEquals(firstGeneration.encapsulationKey.key.fullBytes, secondGeneration.encapsulationKey.key.fullBytes, "Regeneration failed for 512!")
    }

    @Test
    fun regenerationComparison768() {
        val randomSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
        val pkeSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }

        val firstGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768, randomSeed, pkeSeed.copyOf())
        val secondGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768, randomSeed, pkeSeed.copyOf())

        assertContentEquals(firstGeneration.encapsulationKey.key.fullBytes, secondGeneration.encapsulationKey.key.fullBytes, "Regeneration failed for 768!")
    }

    @Test
    fun regenerationComparison1024() {
        val randomSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }
        val pkeSeed = ByteArray(32).apply { CryptoRand.Default.nextBytes(this) }

        val firstGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024, randomSeed, pkeSeed.copyOf())
        val secondGeneration = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024, randomSeed, pkeSeed.copyOf())

        assertContentEquals(firstGeneration.encapsulationKey.key.fullBytes, secondGeneration.encapsulationKey.key.fullBytes, "Regeneration failed for 1024!")
    }

    @Test
    fun modulusIntegrityCheck() {
        for(i in 0..<KyberConstants.Q)
            assertTrue(KyberMath.isModuloOfQ(i), "Good Modulus Integrity check failed!")

        for(i in KyberConstants.Q..<(KyberConstants.Q * 2))
            assertTrue(!KyberMath.isModuloOfQ(i), "Bad Modulus Integrity check failed!")

        for(i in -(KyberConstants.Q * 2)..<0)
            assertTrue(!KyberMath.isModuloOfQ(i), "Negative Modulus Integrity check failed!")
    }

    fun generateRandom256Shorts(seed: Int = 24): IntArray {
        val shorts = IntArray(256)
        val rand = Random(seed)

        for(i in shorts.indices)
            shorts[i] = moduloOf(rand.nextInt(), KyberConstants.Q)

        return shorts
    }

    fun generateRandom32Bytes(seed: Int = 314): ByteArray {
        val bytes = ByteArray(32)
        val rand = Random(seed)

        for(i in bytes.indices)
            bytes[i] = rand.nextBytes(1)[0]

        return bytes
    }

    fun moduloOf(value: Number, modulo: Number): Int {
        val shortedValue = value.toInt()
        val shortedModulo = modulo.toInt()
        val isNegative = shortedValue < 0
        return ((shortedModulo - (abs(shortedValue) % shortedModulo)) * isNegative.int) + ((shortedValue % shortedModulo) * (!isNegative).int)
    }

    fun decomposeShort(int: Int): ByteArray {
        return byteArrayOf(int.toByte(), (int shr 8).toByte())
    }

    fun bytesToBitString(byteArray: ByteArray, bitCount: Int, joiner: String): String {
        var stringOutput = ""
        var count = 0
        for(byte in byteArray) {
            val bits = KyberMath.expandBytesAsBits(byteArrayOf(byte))
            for(bit in bits) {
                stringOutput += bit

                count++

                if(count >= bitCount) {
                    stringOutput += joiner.reversed()
                    count = 0
                }
            }
        }

        return stringOutput.removeSuffix(joiner.reversed()).reversed()
    }

    fun bitsToString(booleanArray: BooleanArray, bitCount: Int, joiner: String): String {
        var stringOutput = ""
        var count = 0
        for(bit in booleanArray) {
            stringOutput += bit.int

            count++

            if(count >= bitCount) {
                stringOutput += joiner
                count = 0
            }
        }

        return stringOutput.removeSuffix(joiner).reversed()
    }
}