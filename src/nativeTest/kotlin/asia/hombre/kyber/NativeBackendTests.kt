package asia.hombre.kyber

import asia.hombre.keccak.api.SHAKE256
import asia.hombre.kyber.exceptions.*
import asia.hombre.kyber.internal.*
import kotlin.test.*

class NativeBackendTests {
    @Test
    fun rustMatchesKotlinForEveryVariant() {
        for (parameter in KyberParameter.entries) repeat(12) { sample ->
            val z = ByteArray(32) { (it + sample + 1).toByte() }
            val d = ByteArray(32) { (3 * it + sample + 1).toByte() }
            val message = ByteArray(32) { (7 * it + sample + 1).toByte() }
            val reference = CommonKyberKeyGenerator.generate(parameter, z, d.copyOf())
            val native = KyberKeyGenerator.generate(parameter, z, d.copyOf())
            assertContentEquals(reference.encapsulationKey.fullBytes, native.encapsulationKey.fullBytes)
            assertContentEquals(reference.decapsulationKey.fullBytes, native.decapsulationKey.fullBytes)

            val expected = CommonKyberAgreement.encapsulate(reference.encapsulationKey, message.copyOf())
            val actual = KyberAgreement.encapsulate(native.encapsulationKey, message.copyOf())
            assertContentEquals(expected.sharedSecretKey, actual.sharedSecretKey)
            assertContentEquals(expected.cipherText.fullBytes, actual.cipherText.fullBytes)
            assertContentEquals(expected.sharedSecretKey, native.decapsulationKey.decapsulate(expected.cipherText))
            assertContentEquals(
                actual.sharedSecretKey,
                CommonKyberAgreement.decapsulate(reference.decapsulationKey, actual.cipherText)
            )

            val pke = KyberKeyGenerator.PKEGenerator.generate(parameter, d.copyOf())
            val coins = ByteArray(32) { (sample + 9).toByte() }
            val ciphertext = KyberAgreement.toCipherText(pke.encryptionKey, message.copyOf(), coins.copyOf())
            val expectedCiphertext =
                CommonKyberAgreement.toCipherText(reference.encapsulationKey.key, message.copyOf(), coins.copyOf())
            assertContentEquals(expectedCiphertext.fullBytes, ciphertext.fullBytes)
            assertContentEquals(message, KyberAgreement.fromCipherText(pke.decryptionKey, ciphertext))
        }
    }

    @Test
    fun modifiedCiphertextsUseImplicitRejection() {
        for (parameter in KyberParameter.entries) {
            val z = ByteArray(32) { (it + 1).toByte() }
            val pair = KyberKeyGenerator.generate(parameter, z, ByteArray(32) { 17 })
            val result = KyberAgreement.encapsulate(pair.encapsulationKey, ByteArray(32) { 29 })
            val original = result.cipherText.fullBytes
            for (position in listOf(0, original.size / 2, original.lastIndex)) {
                for (mask in listOf(1, 0x80, 0xff)) {
                    val modified = original.copyOf().also { it[position] = (it[position].toInt() xor mask).toByte() }
                    val ciphertext = KyberCipherText.fromBytes(modified)
                    val expected = SHAKE256().apply { update(z); update(modified) }.digest()
                    assertContentEquals(
                        expected,
                        pair.decapsulationKey.decapsulate(ciphertext),
                        "$parameter, byte $position, mask $mask"
                    )
                }
            }
        }
    }

    @Test
    fun nativeOperationsBorrowTheExistingStorage() {
        for (parameter in KyberParameter.entries) {
            val pair = KyberKeyGenerator.generate(parameter, ByteArray(32) { 1 }, ByteArray(32) { 2 })
            val dk = pair.decapsulationKey
            val backing = dk.bytes.array
            assertSame(backing, dk.key.keyBytes.array)
            assertSame(backing, pair.encapsulationKey.key.bytes.array)
            assertSame(backing, dk.encryptionKey.nttSeed.array)
            assertSame(backing, dk.hash.array)
            assertSame(backing, dk.randomSeed.array)
            val before = backing.copyOf()
            val result = KyberAgreement.encapsulate(pair.encapsulationKey, ByteArray(32) { 3 })
            val ciphertext = result.cipherText
            assertEquals(KyberConstants.SECRET_KEY_LENGTH, ciphertext.bytes.offset)
            assertSame(ciphertext, result.cipherText)
            val ciphertextBefore = ciphertext.fullBytes
            repeat(3) { assertContentEquals(result.sharedSecretKey, dk.decapsulate(ciphertext)) }
            assertSame(backing, dk.bytes.array)
            assertContentEquals(before, backing)
            assertContentEquals(ciphertextBefore, ciphertext.fullBytes)
            assertSame(ciphertext.encodedCoefficients.array, ciphertext.encodedTerms.array)
        }
    }

    @Test
    fun rustValidatesBorrowedKeysOnEntry() {
        val pair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512, ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val hash = pair.decapsulationKey.hash
        hash.array[hash.offset] = (hash[0].toInt() xor 1).toByte()
        val ciphertext = KyberAgreement.encapsulate(pair.encapsulationKey, ByteArray(32) { 3 }).cipherText
        assertFailsWith<InvalidKyberKeyException> { pair.decapsulationKey.decapsulate(ciphertext) }
        val ek = pair.encapsulationKey.key.keyBytes
        ek.array[ek.offset] = -1
        ek.array[ek.offset + 1] = -1
        assertFailsWith<InvalidKyberKeyException> {
            KyberAgreement.encapsulate(
                pair.encapsulationKey,
                ByteArray(32) { 3 })
        }
    }
}
