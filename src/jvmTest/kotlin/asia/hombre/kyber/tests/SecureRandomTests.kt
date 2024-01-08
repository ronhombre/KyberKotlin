package asia.hombre.kyber.tests

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.KyberMath.Companion.int
import java.security.SecureRandom
import kotlin.test.Ignore
import kotlin.test.Test

@Ignore
class SecureRandomTests {
    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun random() {
        for(i in 0..<1000) {
            val byteArray = ByteArray(32)
            SecureRandom().nextBytes(byteArray)
            println(bytesToBitString(byteArray, 8, ", "))
        }
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