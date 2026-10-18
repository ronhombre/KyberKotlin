package asia.hombre.kyber

import asia.hombre.kyber.exceptions.*
import asia.hombre.kyber.interfaces.RandomProvider
import asia.hombre.kyber.internal.ByteBuffer
import asia.hombre.kyber.internal.KyberAgreement
import kotlin.test.*

class BackendTests {
    @Test
    fun publicApiUsesTheProvidedRandomnessAndPreservesKeys() {
        for (parameter in KyberParameter.entries) {
            var calls = 0
            val provider = object : RandomProvider {
                override fun fillWithRandom(byteArray: ByteArray) {
                    byteArray.fill((++calls).toByte())
                }
            }
            val pair = KyberKeyGenerator.generate(parameter, provider)
            assertEquals(2, calls)
            val expected = KyberKeyGenerator.generate(parameter, ByteArray(32) { 1 }, ByteArray(32) { 2 })
            assertEquals(expected, pair)
            val imported = KyberDecapsulationKey.fromBytes(pair.decapsulationKey.fullBytes)
            val result = pair.encapsulationKey.encapsulate(provider)
            assertEquals(3, calls)
            assertContentEquals(result.sharedSecretKey, imported.decapsulate(result.cipherText))
            assertContentEquals(result.sharedSecretKey, result.cipherText.decapsulate(imported))
        }
    }

    @Test
    fun publicByteImportsAndExportsAreIndependent() {
        for (parameter in KyberParameter.entries) {
            val pair = KyberKeyGenerator.generate(parameter, ByteArray(32) { 1 }, ByteArray(32) { 2 })
            val encodedDk = pair.decapsulationKey.fullBytes
            val encodedEk = pair.encapsulationKey.fullBytes
            val dk = KyberDecapsulationKey.fromBytes(encodedDk)
            val ek = KyberEncapsulationKey.fromBytes(encodedEk)
            encodedDk.fill(0)
            encodedEk.fill(0)
            assertEquals(pair.decapsulationKey, dk)
            assertEquals(pair.encapsulationKey, ek)
            dk.fullBytes.fill(0)
            ek.fullBytes.fill(0)
            assertEquals(pair.decapsulationKey, dk)
            assertEquals(pair.encapsulationKey, ek)
            val copy = dk.copy()
            assertEquals(dk, copy)
            assertEquals(dk.hashCode(), copy.hashCode())
            assertNotSame(dk.bytes.array, copy.bytes.array)
            val result = ek.encapsulate()
            val serialized = result.cipherText.fullBytes
            val ciphertext = KyberCipherText.fromBytes(serialized)
            serialized.fill(0)
            result.sharedSecretKey.fill(0)
            assertContentEquals(result.sharedSecretKey, copy.decapsulate(ciphertext))
        }
    }

    @Test
    fun seedAndMessageConsumptionAndInvalidInputs() {
        val parameter = KyberParameter.ML_KEM_512
        val z = ByteArray(32) { 1 }
        val d = ByteArray(32) { 2 }
        val pair = KyberKeyGenerator.generate(parameter, z, d)
        assertContentEquals(ByteArray(32) { 1 }, z)
        assertContentEquals(ByteArray(32), d)
        val message = ByteArray(32) { 3 }
        KyberAgreement.encapsulate(pair.encapsulationKey, message)
        assertContentEquals(ByteArray(32), message)
        assertFailsWith<RandomBitGenerationException> {
            KyberKeyGenerator.generate(
                parameter,
                ByteArray(32),
                ByteArray(32) { 2 })
        }
        assertFailsWith<RandomBitGenerationException> {
            KyberKeyGenerator.generate(
                parameter,
                ByteArray(32) { 1 },
                ByteArray(32)
            )
        }
        assertFailsWith<RandomBitGenerationException> {
            KyberAgreement.encapsulate(
                pair.encapsulationKey,
                ByteArray(32)
            )
        }
        assertFailsWith<IllegalArgumentException> {
            KyberKeyGenerator.generate(
                parameter,
                ByteArray(31),
                ByteArray(32)
            )
        }
        assertFailsWith<IllegalArgumentException> { KyberAgreement.encapsulate(pair.encapsulationKey, ByteArray(33)) }
        val invalid =
            pair.decapsulationKey.fullBytes.also { it[it.size - 64] = (it[it.size - 64].toInt() xor 1).toByte() }
        assertFailsWith<InvalidKyberKeyException> { KyberDecapsulationKey.fromBytes(invalid) }
        val other = KyberCipherText.fromBytes(ByteArray(KyberParameter.ML_KEM_768.CIPHERTEXT_LENGTH))
        assertFailsWith<MismatchingKyberVariantException> { pair.decapsulationKey.decapsulate(other) }
        assertFailsWith<MismatchingKyberVariantException> { other.decapsulate(pair.decapsulationKey) }
        assertFailsWith<MismatchingKyberVariantException> {
            KyberAgreement.fromCipherText(
                pair.decapsulationKey.key,
                other
            )
        }
    }

    @Test
    fun slicesShareStorageAndEnforceTheirOwnBounds() {
        val array = ByteArray(20) { it.toByte() }
        val view = ByteBuffer(array).slice(4, 16).slice(3, 8)
        assertSame(array, view.array)
        assertEquals(7, view.offset)
        assertContentEquals(byteArrayOf(7, 8, 9, 10, 11), view.copyOf())
        array[7] = 42
        assertEquals(42, view[0].toInt())
        assertFailsWith<IllegalArgumentException> { view.slice(0, 6) }
        assertFailsWith<IllegalArgumentException> { view[-1] }
        assertFailsWith<IllegalArgumentException> { ByteBuffer(array, Int.MAX_VALUE, 1) }
    }
}
