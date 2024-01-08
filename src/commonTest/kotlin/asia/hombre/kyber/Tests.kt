package asia.hombre.kyber

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.KyberMath.Companion.int
import kotlin.test.Test

class Tests {
    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun playground() {
        //val ub = KyberMath.reverseBits(126)
        println("Euclid: " + KyberMath.powMod(3329, -1, 1 shl 16))
        //println("Mod: " + inverse_mod(38, 97))
        //println("Bit Reversed: " + ub)
        //println("Mont 2:" + ((2285 * 17) % 3329))
        //println("Montgomery Reduce: " + montgomeryReduce(-758 * 2226))

        //val time = measureTime { generateInverseExpTable() }.inWholeMilliseconds
        //println("Generation time: {$time}ms")

        //KyberMath.ntt(KyberParameter.makeFromSet(KyberParameter.Set.ML_KEM_768), ByteArray(0))

        val array = shortArrayOf(1, 2, 4, 8, 9, 8, 4095)
        val byteEncoded = KyberMath.byteEncode(array, 12)
        println(4095)
        println(bytesToBitString(byteEncoded, 12, ", "))
        println(KyberMath.byteDecode(byteEncoded, 12).joinToString(", "))

        val keyPairAlice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
        println(keyPairAlice.encapsulationKey.key.fullBytes.size)
        println(keyPairAlice.decapsulationKey.fullBytes.size)

        val keyPairBob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
        println(keyPairBob.encapsulationKey.key.fullBytes.size)
        println(keyPairBob.decapsulationKey.fullBytes.size)

        val agreementAlice = KeyAgreement(keyPairAlice)

        val cipherTextAlice = agreementAlice.encapsulate(keyPairBob.encapsulationKey)

        val agreementBob = KeyAgreement(keyPairBob)

        val cipherTextBob = agreementBob.encapsulate(keyPairAlice.encapsulationKey)

        val secretKeyAlice = agreementAlice.decapsulate(cipherTextBob.cipherText)
        val secretKeyBob = agreementBob.decapsulate(cipherTextAlice.cipherText)

        println(secretKeyAlice.joinToString(", "))
        println(secretKeyBob.joinToString(", "))

        //for(i in 0..<1000)
            //println(bytesToBitString(SecureRandom.generateSecureBytes(32).toUByteArray(), 8, ", "))
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

        return stringOutput.removeSuffix(joiner)
    }
}