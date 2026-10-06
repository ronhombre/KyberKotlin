/*
 * Copyright 2026 Ron Lauren Hombre
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

import asia.hombre.keccak.api.SHAKE256
import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import asia.hombre.kyber.internal.KyberAgreement
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class ImplicitRejectionTest {
    @Test
    fun mismatchedParameterSetsUseVariantException() {
        for (parameter in KyberParameter.entries) {
            val key = keyPair(parameter).decapsulationKey

            // Compare this parameter against all others
            for (other in KyberParameter.entries.filter { it != parameter }) {
                val ciphertext = KyberCipherText.fromBytes(ByteArray(other.CIPHERTEXT_LENGTH))
                assertFailsWith<UnsupportedKyberVariantException> { key.decapsulate(ciphertext) }
                assertFailsWith<UnsupportedKyberVariantException> { ciphertext.decapsulate(key) }
            }
        }
    }

    @Test
    fun validCiphertextsKeepCandidateSecret() {
        for (parameter in KyberParameter.entries) {
            val keyPair = keyPair(parameter)
            val encapsulation = KyberAgreement.encapsulate(
                keyPair.encapsulationKey,
                ByteArray(32) { (it + 1).toByte() }
            )

            assertContentEquals(
                encapsulation.sharedSecretKey,
                keyPair.decapsulationKey.decapsulate(encapsulation.cipherText),
                parameter.name
            )
        }
    }

    @Test
    fun invalidCiphertextsReturnRejectionSecretWithoutThrowing() {
        for (parameter in KyberParameter.entries) {
            val keyPair = keyPair(parameter)
            val encapsulation = KyberAgreement.encapsulate(
                keyPair.encapsulationKey,
                ByteArray(32) { (it + 1).toByte() }
            )

            val original = encapsulation.cipherText.fullBytes
            val corrupted = mutableListOf(ByteArray(original.size), ByteArray(original.size) { -1 })

            // Exercise mismatches at both ends and in the middle, including signed bytes.
            for (offset in listOf(0, original.size / 2, original.lastIndex)) {
                for (bit in listOf(1, 0x80)) {
                    corrupted += original.copyOf().also {
                        it[offset] = (it[offset].toInt() xor bit).toByte()
                    }
                }
            }

            // Check all the outputs against expected values
            for (bytes in corrupted) {
                val expected = SHAKE256().apply {
                    update(keyPair.decapsulationKey.randomSeed)
                    update(bytes)
                }.digest()
                val ciphertext = KyberCipherText.fromBytes(bytes)
                val actual = keyPair.decapsulationKey.decapsulate(ciphertext)
                assertEquals(32, actual.size)
                assertContentEquals(expected, actual, parameter.name)
                assertContentEquals(actual, keyPair.decapsulationKey.decapsulate(ciphertext))
                assertFalse(actual.contentEquals(encapsulation.sharedSecretKey))
            }
        }
    }

    private fun keyPair(parameter: KyberParameter): KyberKEMKeyPair = KyberKeyGenerator.generate(
        parameter,
        ByteArray(32) { (it + 33).toByte() },
        ByteArray(32) { (it + 65).toByte() }
    )
}
