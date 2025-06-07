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
import asia.hombre.keccak.api.SHAKE256
import asia.hombre.kyber.KyberCipherText
import asia.hombre.kyber.KyberConstants
import asia.hombre.kyber.KyberDecapsulationKey
import asia.hombre.kyber.KyberDecryptionKey
import asia.hombre.kyber.KyberEncapsulationKey
import asia.hombre.kyber.KyberEncapsulationResult
import asia.hombre.kyber.KyberEncryptionKey
import asia.hombre.kyber.exceptions.RandomBitGenerationException
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.jvm.JvmSynthetic

/**
 * An agreement class for Encapsulating ML-KEM Keys and Decapsulating Cipher Texts.
 *
 * This class contains K-PKE.Encrypt(), K-PKE.Decrypt(), ML-KEM.Encaps(), and ML-KEM.Decaps() all according to NIST FIPS 203.
 *
 * @constructor Stores the Decapsulation Key for decapsulating later.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
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
        //The important thing here is to prevent anything that has touched the plaintext from being left in memory.
        //Thus, we do not need to zero fill some arrays/matrices.
        //Since randomness is derived from the plaintext, we also zero fill it.
        val parameter = encryptionKey.parameter

        val nttKeyVector = Array(parameter.K) { IntArray(KyberConstants.N) }

        val matrix = Array(parameter.K) { Array(parameter.K) { IntArray(KyberConstants.N) } }
        val randomnessVector = Array(parameter.K) { IntArray(KyberConstants.N) }
        val noiseVector = Array(parameter.K) { IntArray(KyberConstants.N) }

        var constantTerm = IntArray(KyberConstants.N)

        for(i in 0 until parameter.K) {
            nttKeyVector[i] = KyberMath.fastByteDecode(
                encryptionKey.keyBytes,
                12,
                i * KyberConstants.ENCODE_SIZE,
                KyberConstants.ENCODE_SIZE
            )
            KyberMath.vectorToMontVector(nttKeyVector[i])

            randomnessVector[i] = KyberMath.samplePolyCBD(
                parameter.ETA1,
                KyberMath.prf(parameter.ETA1, randomness, i.toByte())
            )
            KyberMath.ntt(randomnessVector[i])

            KyberMath.vectorToVectorAdd(constantTerm, KyberMath.multiplyNTTs(randomnessVector[i], nttKeyVector[i]))

            noiseVector[i] = KyberMath.samplePolyCBD(
                parameter.ETA2,
                KyberMath.prf(parameter.ETA2, randomness, (i + parameter.K).toByte())
            )

            for(j in 0 until parameter.K) {
                matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(encryptionKey.nttSeed, j.toByte(), i.toByte()))
            }
        }

        KyberMath.nttInv(constantTerm)

        val noiseTerm = KyberMath.samplePolyCBD(
            parameter.ETA2,
            KyberMath.prf(parameter.ETA2, randomness, (parameter.K * 2).toByte())
        )

        KyberMath.vectorToVectorAdd(constantTerm, noiseTerm)

        noiseTerm.fill(0) //Security Feature

        val muse = KyberMath.expandMuse(plainText)

        KyberMath.vectorToVectorAdd(constantTerm, muse)

        muse.fill(0) //Security Feature

        val encodedTerms = ByteArray(KyberConstants.N_BYTES * parameter.DV)
        KyberMath.compressAndEncodeInto(encodedTerms, 0, constantTerm, parameter.DV)

        var coefficients = KyberMath.nttMatrixToVectorDot(matrix, randomnessVector, true)
        val encodedCoefficients = ByteArray(KyberConstants.N_BYTES * (parameter.DU * parameter.K))
        for(i in 0 until parameter.K) {
            KyberMath.nttInv(coefficients[i])
            KyberMath.vectorToVectorAdd(coefficients[i], noiseVector[i])
            KyberMath.compressAndEncodeInto(
                encodedCoefficients,
                i * KyberConstants.N_BYTES * parameter.DU,
                coefficients[i],
                parameter.DU
            )

            //Security Features
            noiseVector[i].fill(0)
            randomnessVector[i].fill(0)
        }

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
        val coefficients = Array(kyberCipherText.parameter.K) { IntArray(KyberConstants.N) }

        val secretVector = KyberMath.fastByteDecode(decryptionKey.keyBytes, 12)
        KyberMath.vectorToMontVector(secretVector)

        val constantTerms = KyberMath.fastByteDecode(kyberCipherText.encodedTerms, parameter.DV)
        KyberMath.decompress(constantTerms, parameter.DV)
        KyberMath.vectorToMontVector(constantTerms)

        for (i in 0 until parameter.K) {
            coefficients[i] = KyberMath.fastByteDecode(
                kyberCipherText.encodedCoefficients,
                parameter.DU,
                i * KyberConstants.N_BYTES * parameter.DU,
                KyberConstants.N_BYTES * parameter.DU
            )
            KyberMath.decompress(coefficients[i], parameter.DU)
            KyberMath.vectorToMontVector(coefficients[i])
            KyberMath.ntt(coefficients[i])

            val subtraction = KyberMath.multiplyNTTs(secretVector, coefficients[i], i * KyberConstants.N)
            KyberMath.nttInv(subtraction)

            for (j in 0 until KyberConstants.N) constantTerms[j] -= subtraction[j]
        }

        return ByteArray(KyberConstants.N_BYTES).also { KyberMath.compressAndEncodeInto(it, 0, constantTerms, 1) }
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

        //Security Feature
        recoveredPlainText.fill(0)
        decapsHash.fill(0)

        if(!kyberCipherText.fullBytes.contentEquals(regeneratedCipherText.fullBytes))
            secretKeyCandidate = secretKeyRejection //Implicit Rejection

        return secretKeyCandidate
    }
}