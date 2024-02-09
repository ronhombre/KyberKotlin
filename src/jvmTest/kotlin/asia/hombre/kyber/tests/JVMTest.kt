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
import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.KyberMath.Companion.int
import org.junit.Ignore
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.SecureRandom
import kotlin.io.path.Path

class JVMTest {
    @Test
    fun jvmPlayground() {

    }

    @Test
    fun isGreater() {
        val Q: Short = 3329
        var count = 0
        var correct = 0
        for(i in 0..<UShort.MAX_VALUE.toInt()) {
            count++

            val t1 = (i and 0b0000_1101_0000_0000) == 0b0000_1101_0000_0000
            val t2 = (i and 0b0000_0000_1111_1111).toUShort().countLeadingZeroBits() >= 15
            val t3 = (i and 0b0000_0010_0000_0001).toUShort().countLeadingZeroBits() >= 15
            val t4 = (i and 0b0000_1110_0000_0000) == 0b0000_1110_0000_0000
            val t5 = i != 0b0000_1101_0000_0000

            val test = ((t1 && (t2 || t3)) || t4) && t5
            val guess = i.toUShort().countLeadingZeroBits() < 4 || test
            val certain = i >= Q

            val buffer = ByteBuffer.allocate(UShort.SIZE_BYTES)
            buffer.putShort(i.toShort())

            if(guess == certain) correct++
            else {
                println(i)
                println(bytesToBitString(buffer.array(), 4, ", "))
                println("$certain/$t1/$t2/$t3/$t4")
                //break
            }
        }

        println("Ratio(Correct/Total/Ratio): $correct/$count/" + (correct/count.toDouble() * 100) + "%")
    }

    fun bytesToBitString(byteArray: ByteArray, bitCount: Int, joiner: String): String {
        var stringOutput = ""
        var count = 0
        var temp = ""
        for(byte in byteArray) {
            val bits = KyberMath.bytesToBits(byteArrayOf(byte))
            var tempString = ""
            for(bit in bits) {
                temp += bit.int

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
        Files.write(Path("./random.bin"), org.kotlincrypto.SecureRandom().nextBytesOf(1024 * 1024))
    }

    @Test
    fun jvmEncapsDecaps() {
        val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
        val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

        val agreementAlice = KyberAgreement(keyPairAlice)

        val cipherTextAlice = agreementAlice.encapsulate(keyPairBob.encapsulationKey)

        val agreementBob = KyberAgreement(keyPairBob)

        val cipherTextBob = agreementBob.encapsulate(keyPairAlice.encapsulationKey)

        val secretKeyAlice = agreementAlice.decapsulate(cipherTextBob.cipherText)
        val secretKeyBob = agreementBob.decapsulate(cipherTextAlice.cipherText)

        println("Gen: " + cipherTextAlice.secretKey.joinToString(", "))
        println("Rec: " + secretKeyBob.joinToString(", "))

        println("Gen: " + cipherTextBob.secretKey.joinToString(", "))
        println("Rec: " + secretKeyAlice.joinToString(", "))
    }
}