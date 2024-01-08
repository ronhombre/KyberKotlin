package asia.hombre.kyber.tests

import asia.hombre.kyber.provider.*
import java.security.SecureRandom
import java.util.*
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals

@Ignore
class CompareTests {
    @Test
    fun compareSecretKeys512() {
        println("Comparing Kyber-512")
        compareSecretKeysGeneric(Kyber.KeySize.VARIANT_512)
    }

    @Test
    fun compareSecretKeys768() {
        println("Comparing Kyber-768")
        compareSecretKeysGeneric(Kyber.KeySize.VARIANT_768)
    }

    @Test
    fun compareSecretKeys1024() {
        println("Comparing Kyber-1024")
        compareSecretKeysGeneric(Kyber.KeySize.VARIANT_1024)
    }

    fun compareSecretKeysGeneric(variant: Kyber.KeySize) {
        val pairGen = KyberKeyPairGenerator()
        pairGen.initialize(variant.length, SecureRandom())
        val keyPairAlice = KyberKeyPair.wrap(pairGen.generateKeyPair())
        val keyPairBob = KyberKeyPair.wrap(pairGen.generateKeyPair())
        val keyPairCarol = KyberKeyPair.wrap(pairGen.generateKeyPair())

        val aliceAgreement = KyberKeyAgreement()
        aliceAgreement.engineInit(keyPairAlice.private)

        val bobAgreement = KyberKeyAgreement()
        bobAgreement.engineInit(keyPairBob.private)

        val carolAgreement = KyberKeyAgreement()
        carolAgreement.engineInit(keyPairCarol.private)

        var bobSecretKey = bobAgreement.engineDoPhase(keyPairAlice.public, true)!! as KyberSharedSecretKey
        var aliceSecretKey = aliceAgreement.engineDoPhase(bobAgreement.kyberCipherText!!, true)!! as KyberSharedSecretKey
        var carolSecretKey = carolAgreement.engineDoPhase(aliceAgreement.kyberCipherText!!, true)!! as KyberSharedSecretKey

        println("" + aliceSecretKey.secretKeyBytes.size + " | " + Arrays.toString(aliceSecretKey.secretKeyBytes))
        println("" + bobSecretKey.secretKeyBytes.size + " | " + Arrays.toString(bobSecretKey.secretKeyBytes))
        println("" + carolSecretKey.secretKeyBytes.size + " | " + Arrays.toString(carolSecretKey.secretKeyBytes))

        assertEquals(Arrays.toString(aliceSecretKey.secretKeyBytes), Arrays.toString(bobSecretKey.secretKeyBytes))
    }
}