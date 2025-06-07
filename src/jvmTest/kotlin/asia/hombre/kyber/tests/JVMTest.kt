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
import asia.hombre.kyber.internal.KyberAgreement
import asia.hombre.kyber.internal.KyberMath
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.junit.Ignore
import org.junit.Test
import org.kotlincrypto.random.CryptoRand
import java.nio.file.Files
import java.security.SecureRandom
import java.security.Security
import kotlin.ByteArray
import kotlin.io.path.Path
import kotlin.test.assertContentEquals

class JVMTest {
    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun jvmPlayground() {

    }

    /**
     * Comprehensively Tests this implementation against BouncyCastle's implementation
     */
    @Test
    fun comprehensiveTest() {
        val parametersToTest = listOf(
            KyberParameter.ML_KEM_512 to MLKEMParameters.ml_kem_512,
            KyberParameter.ML_KEM_768 to MLKEMParameters.ml_kem_768,
            KyberParameter.ML_KEM_1024 to MLKEMParameters.ml_kem_1024
        )

        val random = SecureRandom()
        parametersToTest.forEach { parameter ->
            val myParameter = parameter.first
            val bcParameter = parameter.second
            (0 until 10000).forEach { i ->
                val randomSeed = ByteArray(32).also { random.nextBytes(it) }
                val pkeSeed = ByteArray(32).also { random.nextBytes(it) }
                val plaintext = ByteArray(32).also { random.nextBytes(it) }

                val bcKeypair = MLKEMKeyPairGenerator().apply {
                    init(MLKEMKeyGenerationParameters(random, bcParameter))
                }.internalGenerateKeyPair(pkeSeed, randomSeed)
                val bcDecapsKey = bcKeypair.private as MLKEMPrivateKeyParameters
                val bcEncapsKey = bcKeypair.public as MLKEMPublicKeyParameters

                val keypair = KyberKeyGenerator.generate(myParameter, randomSeed, pkeSeed)
                val decapsKey = keypair.decapsulationKey
                val encapsKey = keypair.encapsulationKey

                assertContentEquals(bcDecapsKey.encoded, decapsKey.fullBytes, "Decapsulation Key Different. Test Index: $i")
                assertContentEquals(bcEncapsKey.encoded, encapsKey.fullBytes, "Encapsulation Key Different. Test Index: $i")

                val generator = MLKEMGenerator(random)

                val bcResult = generator.internalGenerateEncapsulated(bcEncapsKey, plaintext)
                val result = KyberAgreement.encapsulate(encapsKey, plaintext)

                assertContentEquals(bcResult.secret, result.sharedSecretKey, "Shared Secret Key Different. Test Index: $i")
                assertContentEquals(bcResult.encapsulation, result.cipherText.fullBytes, "Ciphertext Different. Test Index: $i")

                val decapsResult = result.cipherText.decapsulate(decapsKey)

                assertContentEquals(result.sharedSecretKey, decapsResult, "Decapsulated Shared Secret Key Different. Test Index: $i")
            }
        }
    }

    fun bytesToBitString(byteArray: ByteArray, bitCount: Int, joiner: String): String {
        var stringOutput = ""
        var count = 0
        var temp = ""
        for(byte in byteArray) {
            val bits = KyberMath.expandBytesAsBits(byteArrayOf(byte))
            var tempString = ""
            for(bit in bits) {
                temp += bit

                count++

                if(count >= bitCount) {
                    tempString += temp + joiner.reversed()
                    count = 0
                    temp = ""
                }
            }
            stringOutput += tempString.reversed()
        }

        return stringOutput.removePrefix(joiner)
    }

    @Ignore //Remove
    @Test
    fun jvmCompareSecureRandom() {
        val bytes = ByteArray(1024 * 1024)
        SecureRandom.getInstanceStrong().nextBytes(bytes)
        //Visualize through binvis.io
        Files.write(Path("./randomjvm.bin"), bytes)
        Files.write(Path("./random.bin"), ByteArray(1024 * 1024).apply { CryptoRand.Default.nextBytes(this) })
    }

    @Test
    fun jvmEncapsDecaps() {
        val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
        val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

        val cipherTextAlice = keyPairBob.encapsulationKey.encapsulate()

        val cipherTextBob = keyPairAlice.encapsulationKey.encapsulate()

        val secretKeyAlice = cipherTextBob.cipherText.decapsulate(keyPairAlice.decapsulationKey)
        val secretKeyBob = cipherTextAlice.cipherText.decapsulate(keyPairBob.decapsulationKey)

        println("Gen: " + cipherTextAlice.sharedSecretKey.joinToString(", "))
        println("Rec: " + secretKeyBob.joinToString(", "))

        println("Gen: " + cipherTextBob.sharedSecretKey.joinToString(", "))
        println("Rec: " + secretKeyAlice.joinToString(", "))
    }
}