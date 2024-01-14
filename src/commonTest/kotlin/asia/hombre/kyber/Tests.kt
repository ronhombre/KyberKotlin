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
import asia.hombre.kyber.internal.KyberMath.Companion.int
import asia.hombre.kyber.internal.SecureRandom
import kotlin.random.Random
import kotlin.test.*

class Tests {
    @Test
    fun playground() {
        val keyPairAlice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
        val keyPairBob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)

        val agreementAlice = KeyAgreement(keyPairAlice)

        val cipherTextAlice = agreementAlice.encapsulate(keyPairBob.encapsulationKey)

        val agreementBob = KeyAgreement(keyPairBob)

        val cipherTextBob = agreementBob.encapsulate(keyPairAlice.encapsulationKey)

        val secretKeyAlice = agreementAlice.decapsulate(cipherTextBob.cipherText)
        val secretKeyBob = agreementBob.decapsulate(cipherTextAlice.cipherText)

        println("Gen: " + cipherTextAlice.secretKey.joinToString(", "))
        println("Rec: " + secretKeyBob.joinToString(", "))

        println("Gen: " + cipherTextBob.secretKey.joinToString(", "))
        println("Rec: " + secretKeyAlice.joinToString(", "))
    }

    @Test
    fun pkeEncryptDecrypt() {
        val keyPairAlice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
        val keyPairBob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)

        val agreementAlice = KeyAgreement(keyPairAlice)
        val agreementBob = KeyAgreement(keyPairBob)

        val original = SecureRandom.generateSecureBytes(32)
        val cipher = agreementAlice.encapsulate(keyPairBob.encapsulationKey, original).cipherText
        val recovered = agreementBob.fromCipherText(cipher)

        assertContentEquals(original, recovered, "PKE Encryption and Decryption failed!")
    }

    @Test
    fun ntt() {
        val vectors = generateRandom256Shorts()
        val nttVectors = KyberMath.NTT(vectors)
        val recoveredVectors = KyberMath.invNTT(nttVectors)

        assertContentEquals(vectors, recoveredVectors, "Conversion to NTT and inversion failed!")
    }

    @Test
    fun byteEncoding() {
        val shorts = generateRandom256Shorts()
        val encodedBytes = KyberMath.byteEncode(shorts, 12)
        val decodedBytes = KyberMath.byteDecode(encodedBytes, 12)

        assertContentEquals(shorts, decodedBytes, "Byte Encoding and Decoding failed!")
    }

    @Test
    fun regenerationComparison() {
        val randomSeed = SecureRandom.generateSecureBytes(32)
        val pkeSeed = SecureRandom.generateSecureBytes(32)

        val firstGeneration = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512, randomSeed, pkeSeed)
        val secondGeneration = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512, randomSeed, pkeSeed)

        assertContentEquals(firstGeneration.encapsulationKey.key.fullBytes, secondGeneration.encapsulationKey.key.fullBytes, "Regeneration failed!")
    }

    fun generateRandom256Shorts(): ShortArray {
        val shorts = ShortArray(256)
        val rand = Random(24)

        for(i in shorts.indices)
            shorts[i] = KyberMath.moduloOf(rand.nextInt().toShort(), KyberConstants.Q)

        return shorts
    }

    fun brv(x: Int): Int {
        // Reverses a 7-bit number
        val binaryString = buildString {
            var num = x
            repeat(7) {
                append(num and 1)
                num = num shr 1
            }
        }
        return binaryString.toInt(2)
    }

    fun bytesToBitString(byteArray: ByteArray, bitCount: Int, joiner: String): String {
        var stringOutput = ""
        var count = 0
        for(byte in byteArray) {
            val bits = KyberMath.bytesToBits(byteArrayOf(byte))
            for(bit in bits) {
                stringOutput += bit.int

                count++

                if(count >= bitCount) {
                    stringOutput += joiner
                    count = 0
                }
            }
        }

        return stringOutput.removeSuffix(joiner).reversed()
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