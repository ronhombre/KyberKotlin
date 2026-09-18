/*
 * Copyright 2025 Ron Lauren Hombre
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

package asia.hombre.kyber.internal

import asia.hombre.keccak.api.SHA3_256
import asia.hombre.keccak.api.SHA3_512
import asia.hombre.keccak.api.SHAKE128
import asia.hombre.keccak.api.SHAKE256
import asia.hombre.kyber.KyberCipherText
import asia.hombre.kyber.KyberConstants
import asia.hombre.kyber.KyberDecapsulationKey
import asia.hombre.kyber.KyberDecryptionKey
import asia.hombre.kyber.KyberEncapsulationKey
import asia.hombre.kyber.KyberEncapsulationResult
import asia.hombre.kyber.KyberEncryptionKey
import asia.hombre.kyber.exceptions.RandomBitGenerationException
import kotlin.jvm.JvmSynthetic

/**
 * An agreement class for Encapsulating ML-KEM Keys and Decapsulating Cipher Texts.
 *
 * This class contains K-PKE.Encrypt(), K-PKE.Decrypt(), ML-KEM.Encaps(), and ML-KEM.Decaps() all according to NIST FIPS 203.
 *
 * @constructor Stores the Decapsulation Key for decapsulating later.
 * @author Ron Lauren Hombre
 */
internal object KyberAgreement {
    /**
     * Private Encryption function.
     *
     * This method is the K-PKE.Encrypt() specified in NIST FIPS 203.
     *
     * @param encryptionKey [KyberEncryptionKey] of the second party.
     * @param plainText [ByteArray] Plain Text to encrypt.
     * @param randomness [ByteArray] Random bytes as random source.
     * @return [KyberCipherText] - The Cipher Text to send to the second party.
     */
    private fun toCipherText(encryptionKey: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        val parameter = encryptionKey.parameter

        val constantTerm = IntArray(KyberConstants.N)
        val coefficients = Array(parameter.K) { IntArray(KyberConstants.N) }

        val tempBuffer = IntArray(KyberConstants.N)
        val randomnessElement = IntArray(KyberConstants.N)
        val xof = SHAKE128()
        val prf = SHAKE256()

        for(i in 0 until parameter.K) {
            KyberMath.fastByteDecodeInto(
                tempBuffer,
                encryptionKey.keyBytes,
                12,
                i * KyberConstants.ENCODE_SIZE,
                KyberConstants.ENCODE_SIZE
            )
            KyberMath.vectorToMontVector(tempBuffer)
            KyberMath.samplePolyCBDInto(
                randomnessElement,
                parameter.ETA1,
                prf.apply {
                    update(randomness)
                    update(i.toByte())
                }.stream().nextBytes(KyberConstants.QUART_N * parameter.ETA1)
            )
            KyberMath.ntt(randomnessElement)

            KyberMath.multiplyNTTsInto(constantTerm, randomnessElement, tempBuffer)

            for(j in 0 until parameter.K) {
                KyberMath.sampleNTTInto(
                    tempBuffer,
                    xof.apply {
                        update(encryptionKey.nttSeed)
                        update(j.toByte())
                        update(i.toByte())
                    }.stream()
                )
                KyberMath.multiplyNTTsInto(coefficients[j], tempBuffer, randomnessElement)
            }

            randomnessElement.fill(0) //Security Feature
        }

        for(i in 0 until parameter.K) {
            for(k in 0 until KyberConstants.N) {
                coefficients[i][k] = KyberMath.barrettReduce(coefficients[i][k])
            }
        }

        KyberMath.nttInv(constantTerm)

        KyberMath.samplePolyCBDInto(
            tempBuffer,
            parameter.ETA2,
            prf.apply {
                update(randomness)
                update((parameter.K * 2).toByte())
            }.stream().nextBytes(KyberConstants.QUART_N * parameter.ETA2)
        )

        KyberMath.vectorToVectorAdd(constantTerm, tempBuffer)

        val muse = KyberMath.expandMuse(plainText)
        plainText.fill(0) //Security Feature

        KyberMath.vectorToVectorAdd(constantTerm, muse)
        muse.fill(0) //Security Feature

        val encodedTerms = ByteArray(KyberConstants.N_BYTES * parameter.DV)
        KyberMath.compressAndEncodeInto(encodedTerms, 0, constantTerm, parameter.DV)

        val encodedCoefficients = ByteArray(KyberConstants.N_BYTES * (parameter.DU * parameter.K))
        for(i in 0 until parameter.K) {
            KyberMath.nttInv(coefficients[i])

            KyberMath.samplePolyCBDInto(
                tempBuffer,
                parameter.ETA2,
                prf.apply {
                    update(randomness)
                    update((i + parameter.K).toByte())
                }.stream().nextBytes(KyberConstants.QUART_N * parameter.ETA2)
            )

            KyberMath.vectorToVectorAdd(coefficients[i], tempBuffer)

            KyberMath.compressAndEncodeInto(
                encodedCoefficients,
                i * KyberConstants.N_BYTES * parameter.DU,
                coefficients[i],
                parameter.DU
            )
        }

        tempBuffer.fill(0) //Security Feature
        randomness.fill(0) //Security Feature

        return KyberCipherText(parameter, encodedCoefficients, encodedTerms)
    }

    /**
     * Internal Decryption function for testing purposes.
     *
     * This method is the K-PKE.Decrypt() specified in NIST FIPS 203.
     *
     * @param decryptionKey [KyberDecryptionKey] from yourself.
     * @param kyberCipherText [KyberCipherText] from the second party.
     * @return [ByteArray] - The recovered Plain Text.
     */
    @JvmSynthetic
    internal fun fromCipherText(decryptionKey: KyberDecryptionKey, kyberCipherText: KyberCipherText): ByteArray {
        val parameter = kyberCipherText.parameter

        val coefficient = IntArray(KyberConstants.N)

        val secretVector = IntArray((decryptionKey.keyBytes.size shl 1) / 3)
        KyberMath.fastByteDecodeInto(secretVector, decryptionKey.keyBytes, 12)
        KyberMath.vectorToMontVector(secretVector)

        val constantTerms = IntArray((kyberCipherText.encodedTerms.size * 8) / parameter.DV)
        KyberMath.fastByteDecodeInto(
            constantTerms,
            kyberCipherText.encodedTerms,
            parameter.DV,
            decompress = true
        )
        KyberMath.vectorToMontVector(constantTerms)

        val subtraction = IntArray(KyberConstants.N)
        for (i in 0 until parameter.K) {
            KyberMath.fastByteDecodeInto(
                coefficient,
                kyberCipherText.encodedCoefficients,
                parameter.DU,
                i * KyberConstants.N_BYTES * parameter.DU,
                KyberConstants.N_BYTES * parameter.DU,
                true
            )
            KyberMath.vectorToMontVector(coefficient)
            KyberMath.ntt(coefficient)

            KyberMath.multiplyNTTsInto(subtraction, secretVector, coefficient, i * KyberConstants.N)
        }

        KyberMath.nttInv(subtraction)

        for (j in 0 until KyberConstants.N) {
            constantTerms[j] -= subtraction[j]
        }

        return ByteArray(KyberConstants.N_BYTES).also {
            KyberMath.compressAndEncodeInto(it, 0, constantTerms, 1)
        }
    }

    /**
     * Internal Encapsulation function for testing purposes.
     *
     * This method is the ML-KEM.Encaps_internal() specified in NIST FIPS 203.
     *
     * @param kyberEncapsulationKey [KyberEncapsulationKey] of the second party.
     * @param plainText [ByteArray] The Plain Text to use.
     * @return [KyberEncapsulationResult] - Contains the Cipher Text and the generated Shared Secret Key.
     */
    @JvmSynthetic
    internal fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult {
        if(plainText.fold(true) { acc, it -> acc and (it == 0.toByte()) })
            throw RandomBitGenerationException()

        val sharedKeyAndRandomness = SHA3_512().apply {
            update(plainText)
            update(SHA3_256().digest(kyberEncapsulationKey.key.fullBytes))
        }.digest()

        val cipherText = toCipherText(kyberEncapsulationKey.key, plainText, sharedKeyAndRandomness.copyOfRange(KyberConstants.SECRET_KEY_LENGTH, sharedKeyAndRandomness.size))
        plainText.fill(0) //Security feature

        return KyberEncapsulationResult(sharedKeyAndRandomness.copyOfRange(0, KyberConstants.SECRET_KEY_LENGTH), cipherText)
    }

    /**
     * Internal Decapsulation function for testing purposes.
     *
     * This method is the ML-KEM.Decaps_internal() specified in NIST FIPS 203.
     *
     * @param decapsulationKey [KyberDecapsulationKey] from yourself.
     * @param kyberCipherText [KyberCipherText] received from sender.
     * @return [ByteArray] - The generated Shared Secret Key, which is the same one generated by the sender.
     */
    @JvmSynthetic
    internal fun decapsulate(decapsulationKey: KyberDecapsulationKey, kyberCipherText: KyberCipherText): ByteArray {
        val recoveredPlainText = fromCipherText(decapsulationKey.key, kyberCipherText)

        val decapsHash = SHA3_512().apply {
            update(recoveredPlainText)
            update(decapsulationKey.hash)
        }.digest()

        val secretKeyRejection = SHAKE256().apply {
            update(decapsulationKey.randomSeed)
            update(kyberCipherText.fullBytes)
        }.digest()

        var secretKeyCandidate = decapsHash.copyOfRange(0, KyberConstants.SECRET_KEY_LENGTH)

        val regeneratedCipherText = toCipherText(
            decapsulationKey.encryptionKey,
            recoveredPlainText,
            decapsHash.copyOfRange(KyberConstants.SECRET_KEY_LENGTH, decapsHash.size)
        )

        recoveredPlainText.fill(0) //Security Feature
        decapsHash.fill(0) //Security Feature

        if(!kyberCipherText.fullBytes.contentEquals(regeneratedCipherText.fullBytes))
            secretKeyCandidate = secretKeyRejection //Implicit Rejection

        return secretKeyCandidate
    }
}